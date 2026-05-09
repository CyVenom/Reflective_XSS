"""
High-performance async web crawler for injection-point discovery.

Architecture
------------
* **Worker pool** — :attr:`CrawlerConfig.concurrency` async workers drain a
  shared ``asyncio.Queue`` concurrently, enabling true parallelism within a
  single event loop.  Workers call ``queue.task_done()`` only after enqueuing
  any new child URLs, so ``queue.join()`` guarantees the crawl is complete.

* **Rate limiter** — per-domain token bucket enforces
  :attr:`CrawlerConfig.rate_limit` requests per second, preventing hammering
  of any single host.

* **robots.txt** — fetched once per origin, cached in-process; disallowed paths
  are skipped when :attr:`CrawlerConfig.respect_robots` is ``True``.

* **URL normaliser** — strips fragments, lowercases scheme/host, removes default
  ports, strips tracking query-params (utm_*, gclid, …), sorts remaining params
  alphabetically, and stores a param-name fingerprint for structural dedup so
  ``?id=1`` and ``?id=2`` aren't both queued.

* **JS endpoint extractor** — regex-scans inline ``<script>`` blocks and linked
  ``.js`` files for fetch/axios/XHR call paths, URL string literals, and
  ``URLSearchParams`` usage to surface API endpoints not reachable via links.

* **Parameter miner** — harvests parameter names from JS source, inline JSON
  ``<script type="application/json">`` blocks, and ``<input name="...">``
  elements outside forms, then synthesises a testable URL for the scanner.

Backward compatibility
----------------------
The public API — ``Crawler``, ``CrawlResult``, ``Form``, ``FormField`` — is
unchanged from the original module.  ``CrawlResult.js_endpoints`` and
``CrawlResult.errors`` are new additions.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import (
    parse_qs,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)
from urllib.robotparser import RobotFileParser

from bs4 import BeautifulSoup, Tag

from core.config import CrawlerConfig
from utils.http import HTTPClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Tracking / analytics params that carry no application state
_TRACKING_PARAMS: frozenset[str] = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "utm_id", "utm_source_platform", "fbclid", "gclid", "gclsrc", "msclkid",
    "mc_eid", "mc_cid", "_ga", "_gl", "ref", "referrer", "source",
    "dclid", "wbraid", "gbraid", "_hsenc", "_hsmi", "hsCtaTracking",
})

# Extensions that never produce HTML/JS worth crawling
_SKIP_EXTENSIONS: frozenset[str] = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".zip", ".tar", ".gz", ".rar", ".7z",
    ".mp3", ".mp4", ".avi", ".mov", ".webm", ".ogg",
    ".exe", ".dll", ".bin", ".dmg", ".apk",
    ".map",   # JS source-maps
    ".txt",   # usually not interesting; robots.txt is fetched separately
    ".xml",   # sitemaps handled separately if needed
})

# JS patterns for endpoint and parameter extraction
_JS_FETCH_RE = re.compile(
    r"""(?:fetch\s*\(\s*|
           axios\.(?:get|post|put|delete|patch|request)\s*\(\s*|
           \$\.(?:ajax|get|post)\s*\(\s*(?:\{[^}]*url\s*:\s*)?|
           (?:url|href|endpoint|apiUrl|api_url|baseUrl|BASE_URL|API_URL)
             \s*[:=]\s*)
        ['"`]([^'"`\s]{1,300})['"`]""",
    re.VERBOSE | re.IGNORECASE,
)
_JS_API_PATH_RE = re.compile(
    r"""['"`]((?:/api|/v\d+|/rest|/graphql|/endpoint|/service|/data|/query)
         [^'"`\s]{0,200})['"`]""",
    re.VERBOSE | re.IGNORECASE,
)
_URL_SEARCH_PARAMS_RE = re.compile(
    r"""new\s+URLSearchParams\s*\(\s*\{([^}]{0,600})\}""",
    re.DOTALL,
)
_PARAM_KEY_RE = re.compile(
    r"""['"]([a-zA-Z_][a-zA-Z0-9_\-]{0,49})['"]\s*:"""
)
_INLINE_JSON_BLOCK_RE = re.compile(
    r"""<script[^>]+type=['"]application/json['"][^>]*>([\s\S]{1,8192})</script>""",
    re.IGNORECASE,
)
_DATA_PARAM_ATTR_RE = re.compile(r"^data-(?:param-?|key$|field$)(.*)$")


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FormField:
    """A single input element within an HTML form."""

    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class Form:
    """A discovered HTML form with its injectable fields."""

    action: str
    method: str  # "GET" or "POST"
    fields: list[FormField] = field(default_factory=list)

    def injectable_fields(self) -> list[FormField]:
        """Return only fields that can carry arbitrary user input."""
        skip = {"hidden", "submit", "button", "image", "reset", "file"}
        return [f for f in self.fields if f.input_type.lower() not in skip]


@dataclass
class JavaScriptEndpoint:
    """An API endpoint or parameterised URL extracted from JavaScript source."""

    url: str
    """Absolute URL of the discovered endpoint."""

    source_page: str
    """Page URL where this endpoint was found."""

    params: list[str] = field(default_factory=list)
    """Parameter names extracted via URLSearchParams / JSON mining."""


@dataclass
class CrawlResult:
    """Everything the crawler discovered, ready for the scanning engine."""

    base_url: str
    urls_with_params: list[str] = field(default_factory=list)
    """Parameterised page URLs (query string present)."""

    forms: list[Form] = field(default_factory=list)
    """HTML forms discovered across all visited pages."""

    js_endpoints: list[JavaScriptEndpoint] = field(default_factory=list)
    """Endpoints mined from JavaScript source."""

    visited: set[str] = field(default_factory=set)
    """Set of normalised URLs that were fetched."""

    errors: list[str] = field(default_factory=list)
    """Non-fatal errors encountered during the crawl."""

    @property
    def all_scan_urls(self) -> list[str]:
        """
        Unified, deduplicated list of every URL worth passing to the scanner.
        Includes both directly discovered parameterised URLs and JS endpoint URLs.
        """
        seen: set[str] = set()
        out: list[str] = []
        for url in self.urls_with_params:
            if url not in seen:
                seen.add(url)
                out.append(url)
        for ep in self.js_endpoints:
            if ep.url not in seen and urlparse(ep.url).query:
                seen.add(ep.url)
                out.append(ep.url)
        return out


# ---------------------------------------------------------------------------
# Shared crawl state (encapsulates all mutable data touched by workers)
# ---------------------------------------------------------------------------


@dataclass
class _CrawlState:
    result: CrawlResult
    visited_norm: set[str]        # normalised URLs already enqueued / fetched
    param_fps: set[str]           # param-name fingerprints for structural dedup
    lock: asyncio.Lock


# ---------------------------------------------------------------------------
# Per-domain rate limiter (token bucket)
# ---------------------------------------------------------------------------


class _DomainRateLimiter:
    """
    Enforces a maximum requests-per-second rate on a per-domain basis.

    Uses a simple token-bucket: each domain starts with one token; new tokens
    accumulate at ``rate`` per second.  A caller that arrives before the next
    token is due sleeps for the remainder.
    """

    def __init__(self, rate: float) -> None:
        self._rate = rate  # tokens per second (0 = disabled)
        self._next: dict[str, float] = {}  # domain → earliest next-request time
        self._lock = asyncio.Lock()

    async def acquire(self, domain: str) -> None:
        if self._rate <= 0:
            return
        async with self._lock:
            now = time.monotonic()
            ready_at = max(now, self._next.get(domain, 0.0))
            interval = 1.0 / self._rate
            self._next[domain] = ready_at + interval
            wait = ready_at - now
        if wait > 0:
            await asyncio.sleep(wait)


# ---------------------------------------------------------------------------
# robots.txt cache (one RobotFileParser per origin)
# ---------------------------------------------------------------------------


class _RobotsCache:
    """
    Fetches ``/robots.txt`` for each origin once and caches the result.
    Missing or non-200 robots.txt is treated as "allow all".
    """

    def __init__(self, http: HTTPClient, user_agent: str) -> None:
        self._http = http
        self._ua = user_agent
        self._cache: dict[str, RobotFileParser] = {}
        self._lock = asyncio.Lock()

    async def allowed(self, url: str) -> bool:
        origin = _origin(url)
        async with self._lock:
            if origin not in self._cache:
                self._cache[origin] = await self._fetch(origin)
        return self._cache[origin].can_fetch(self._ua, url)

    async def _fetch(self, origin: str) -> RobotFileParser:
        rp = RobotFileParser()
        rp.set_url(f"{origin}/robots.txt")
        resp = await self._http.get(f"{origin}/robots.txt")
        if resp and resp.status < 400:
            rp.parse(resp.text.splitlines())
        else:
            rp.parse([])  # no robots.txt → allow all
        return rp


# ---------------------------------------------------------------------------
# URL utilities
# ---------------------------------------------------------------------------


def _origin(url: str) -> str:
    """Return ``scheme://host[:port]`` for *url*."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _normalize_url(url: str) -> str:
    """
    Return a canonical form of *url* suitable for deduplication.

    Transformations applied:
    - Strip URL fragment
    - Lowercase scheme and host
    - Remove default port (80 for HTTP, 443 for HTTPS)
    - Strip known tracking query parameters
    - Sort remaining query parameters alphabetically
    - Remove trailing path slash (except bare root ``/``)
    """
    p = urlparse(url)
    scheme = p.scheme.lower()
    host = (p.hostname or "").lower()
    port = p.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = host
    elif port:
        netloc = f"{host}:{port}"
    else:
        netloc = host

    path = p.path.rstrip("/") or "/"
    qs = {k: v for k, v in parse_qs(p.query, keep_blank_values=True).items()
          if k not in _TRACKING_PARAMS}
    sorted_query = urlencode(sorted(qs.items()), doseq=True)
    return urlunparse((scheme, netloc, path, "", sorted_query, ""))


def _param_fingerprint(url: str) -> str:
    """
    Structural URL fingerprint that ignores parameter *values*.

    ``?id=1`` and ``?id=99`` produce the same fingerprint so we don't queue
    the same injection point twice with different fuzz values.
    """
    p = urlparse(url)
    keys = sorted(k for k in parse_qs(p.query, keep_blank_values=True)
                  if k not in _TRACKING_PARAMS)
    return f"{p.scheme}://{p.netloc}{p.path}?{'&'.join(keys)}"


def _should_skip(url: str) -> bool:
    """Return True if the URL should never be fetched (bad scheme or extension)."""
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        return True
    m = re.search(r'\.[a-z0-9]+$', p.path.lower())
    return bool(m and m.group() in _SKIP_EXTENSIONS)


# ---------------------------------------------------------------------------
# JavaScript endpoint and parameter extractor
# ---------------------------------------------------------------------------


class _JSExtractor:
    """
    Regex-based extractor that mines JavaScript source for:

    - API endpoint paths referenced in fetch / axios / XHR calls
    - ``/api/...`` style path literals
    - Parameter names declared in ``URLSearchParams({...})`` calls
    - Parameter names in ``<script type="application/json">`` data blocks
    """

    def extract_endpoints(
        self, js_text: str, base_url: str
    ) -> list[tuple[str, list[str]]]:
        """
        Return ``[(absolute_url, [param_names])]`` found in *js_text*.
        Only paths that carry a query string are returned.
        Deduplication is structural (path + sorted param names), so
        ``/api?q=1`` and ``/api?q=2`` produce only one entry.
        """
        results: list[tuple[str, list[str]]] = []
        seen_fps: set[str] = set()  # structural fingerprints

        for pattern in (_JS_FETCH_RE, _JS_API_PATH_RE):
            for m in pattern.finditer(js_text):
                path = m.group(1).strip()
                if not path:
                    continue
                absolute = self._resolve(path, base_url)
                if not absolute or not urlparse(absolute).query:
                    continue
                fp = _param_fingerprint(absolute)
                if fp not in seen_fps:
                    seen_fps.add(fp)
                    results.append((absolute, []))

        return results

    def mine_params(self, js_text: str) -> list[str]:
        """Extract parameter names from ``URLSearchParams({...})`` calls."""
        params: set[str] = set()
        for m in _URL_SEARCH_PARAMS_RE.finditer(js_text):
            for km in _PARAM_KEY_RE.finditer(m.group(1)):
                params.add(km.group(1))
        return list(params)

    def extract_json_block_params(self, html_text: str) -> list[str]:
        """Extract keys from ``<script type="application/json">`` data blocks."""
        params: set[str] = set()
        for m in _INLINE_JSON_BLOCK_RE.finditer(html_text):
            for km in _PARAM_KEY_RE.finditer(m.group(1)):
                params.add(km.group(1))
        return list(params)

    @staticmethod
    def _resolve(path: str, base_url: str) -> Optional[str]:
        if path.startswith(("http://", "https://")):
            return path
        if path.startswith("/"):
            return _origin(base_url) + path
        return None  # relative paths without a base path are unreliable


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------


class Crawler:
    """
    High-performance breadth-first async web crawler.

    ``concurrency`` async workers share a single ``asyncio.Queue``.  Each
    worker picks up a ``(url, depth)`` item, fetches and processes the page,
    enqueues newly-discovered child URLs (if within depth limit), then calls
    ``task_done()``.  ``queue.join()`` is used for clean termination: it
    blocks until every enqueued item has been processed and marked done,
    including those added mid-crawl by workers.

    Usage::

        async with HTTPClient(config.scanner) as http:
            crawler = Crawler(config.crawler, http)
            result = await crawler.crawl("https://example.com/?q=test")
            # result.urls_with_params → feed to Scanner
            # result.forms           → feed to Scanner
    """

    def __init__(self, config: CrawlerConfig, http_client: HTTPClient) -> None:
        self._cfg = config
        self._http = http_client
        self._js = _JSExtractor()
        self._rate = _DomainRateLimiter(config.rate_limit)
        self._robots = _RobotsCache(http_client, config.user_agent)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl *start_url* breadth-first and return all discovered injection points.

        Args:
            start_url: Seed URL.  The crawl is bounded to its origin unless
                       :attr:`CrawlerConfig.follow_external` is ``True``.

        Returns:
            :class:`CrawlResult` with parameterised URLs, forms, and JS endpoints.
        """
        norm_start = _normalize_url(start_url)
        result = CrawlResult(base_url=start_url)
        state = _CrawlState(
            result=result,
            visited_norm={norm_start},
            param_fps=set(),
            lock=asyncio.Lock(),
        )
        base_origin = _origin(start_url)

        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((norm_start, 0))

        # Concurrency semaphore (limits simultaneous HTTP requests)
        sem = asyncio.Semaphore(self._cfg.concurrency)

        async def worker() -> None:
            while True:
                item = await queue.get()
                try:
                    await self._process(item[0], item[1], base_origin, state, queue, sem)
                except Exception as exc:
                    logger.debug("Worker error on %s: %s", item[0], exc)
                    async with state.lock:
                        state.result.errors.append(f"{item[0]}: {exc}")
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self._cfg.concurrency)]
        await queue.join()
        for w in workers:
            w.cancel()
        await asyncio.gather(*workers, return_exceptions=True)

        logger.info(
            "Crawl finished — visited=%d param_urls=%d forms=%d js_endpoints=%d errors=%d",
            len(result.visited),
            len(result.urls_with_params),
            len(result.forms),
            len(result.js_endpoints),
            len(result.errors),
        )
        return result

    # ------------------------------------------------------------------
    # Per-URL processing
    # ------------------------------------------------------------------

    async def _process(
        self,
        url: str,
        depth: int,
        base_origin: str,
        state: _CrawlState,
        queue: asyncio.Queue,
        sem: asyncio.Semaphore,
    ) -> None:
        # Hard page-count cap
        async with state.lock:
            if len(state.result.visited) >= self._cfg.max_pages:
                return

        if _should_skip(url):
            return

        # robots.txt
        if self._cfg.respect_robots:
            if not await self._robots.allowed(url):
                logger.debug("Disallowed by robots.txt: %s", url)
                return

        # Per-domain rate limiting
        await self._rate.acquire(urlparse(url).netloc)

        async with sem:
            response = await self._http.get(url)

        async with state.lock:
            state.result.visited.add(url)

        if response is None:
            async with state.lock:
                state.result.errors.append(f"No response: {url}")
            return

        # Log parameterised URLs (structural dedup via param-name fingerprint)
        if urlparse(url).query:
            fp = _param_fingerprint(url)
            async with state.lock:
                if fp not in state.param_fps:
                    state.param_fps.add(fp)
                    state.result.urls_with_params.append(url)

        # Route by content type
        ct = response.headers.get("Content-Type", "").lower()

        if "javascript" in ct or url.endswith(".js"):
            await self._handle_js_response(response.text, url, state)
            return

        if ct and "html" not in ct:
            return  # binary / CSS / other non-parseable content

        # HTML processing
        soup = BeautifulSoup(response.text, "html.parser")

        forms = self._extract_forms(soup, url)
        async with state.lock:
            state.result.forms.extend(forms)

        if self._cfg.js_extraction:
            js_eps = self._extract_js_endpoints(soup, response.text, url)
            async with state.lock:
                state.result.js_endpoints.extend(js_eps)

        if self._cfg.parameter_mining:
            await self._mine_parameters(soup, response.text, url, state)

        # Enqueue child links
        if depth < self._cfg.max_depth:
            links = self._extract_links(soup, url, base_origin)
            async with state.lock:
                for link in links:
                    norm = _normalize_url(link)
                    if norm not in state.visited_norm:
                        page_limit_ok = len(state.result.visited) < self._cfg.max_pages
                        if page_limit_ok:
                            state.visited_norm.add(norm)
                            await queue.put((norm, depth + 1))

    async def _handle_js_response(
        self, text: str, url: str, state: _CrawlState
    ) -> None:
        """Process a standalone JavaScript file response."""
        endpoints = self._js.extract_endpoints(text, url)
        mined_params = self._js.mine_params(text)
        async with state.lock:
            for ep_url, _ in endpoints:
                state.result.js_endpoints.append(
                    JavaScriptEndpoint(url=ep_url, source_page=url, params=mined_params)
                )

    # ------------------------------------------------------------------
    # Extraction helpers
    # ------------------------------------------------------------------

    def _extract_links(
        self, soup: BeautifulSoup, base_url: str, base_origin: str
    ) -> list[str]:
        """
        Collect every navigable link from a parsed page.

        Sources: ``<a href>``, ``<area href>``, ``<link href>``,
        ``<frame src>``, ``<iframe src>``, ``<script src>``, META refresh.
        """
        links: list[str] = []

        _LINK_ATTRS: list[tuple[str, str]] = [
            ("a",      "href"),
            ("area",   "href"),
            ("link",   "href"),
            ("frame",  "src"),
            ("iframe", "src"),
            ("script", "src"),
        ]
        for tag_name, attr in _LINK_ATTRS:
            for tag in soup.find_all(tag_name, **{attr: True}):
                raw = tag[attr]
                if not isinstance(raw, str):
                    continue
                absolute = urljoin(base_url, raw).split("#")[0]
                if self._accept_url(absolute, base_origin):
                    links.append(absolute)

        # META refresh redirect
        for meta in soup.find_all(
            "meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)}
        ):
            content = meta.get("content", "")
            m = re.search(r"url=(.+)", content, re.IGNORECASE)
            if m:
                absolute = urljoin(base_url, m.group(1).strip()).split("#")[0]
                if self._accept_url(absolute, base_origin):
                    links.append(absolute)

        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[Form]:
        """Parse all ``<form>`` elements into :class:`Form` objects."""
        forms: list[Form] = []
        for form_tag in soup.find_all("form"):
            action = urljoin(page_url, form_tag.get("action") or page_url)
            method = (form_tag.get("method") or "GET").strip().upper()
            fields: list[FormField] = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                fields.append(FormField(
                    name=name,
                    input_type=(inp.get("type") or "text").lower(),
                    value=inp.get("value") or "",
                ))
            if fields:
                forms.append(Form(action=action, method=method, fields=fields))
        return forms

    def _extract_js_endpoints(
        self, soup: BeautifulSoup, html_text: str, page_url: str
    ) -> list[JavaScriptEndpoint]:
        """Mine inline ``<script>`` blocks for endpoint URLs and param names."""
        endpoints: list[JavaScriptEndpoint] = []
        seen_urls: set[str] = set()

        for script in soup.find_all("script", src=False):
            src = script.get_text()
            if not src.strip():
                continue
            mined_params = self._js.mine_params(src)
            for ep_url, _ in self._js.extract_endpoints(src, page_url):
                if ep_url not in seen_urls:
                    seen_urls.add(ep_url)
                    endpoints.append(JavaScriptEndpoint(
                        url=ep_url,
                        source_page=page_url,
                        params=list(set(mined_params)),
                    ))

        # Inline JSON data blocks
        json_params = self._js.extract_json_block_params(html_text)
        if json_params and urlparse(page_url).query:
            endpoints.append(JavaScriptEndpoint(
                url=page_url, source_page=page_url, params=json_params,
            ))

        return endpoints

    async def _mine_parameters(
        self,
        soup: BeautifulSoup,
        html_text: str,
        page_url: str,
        state: _CrawlState,
    ) -> None:
        """
        Synthesise a testable URL by appending all parameter names found on
        the page — from input names, JS URLSearchParams usage, and data-*
        attributes — as empty-valued query parameters.
        """
        mined: set[str] = set()

        # From <input name="..."> elements (even those outside forms)
        for inp in soup.find_all(["input", "select", "textarea"]):
            name = inp.get("name")
            if name:
                mined.add(name)

        # From inline <script> URLSearchParams usage
        for script in soup.find_all("script", src=False):
            mined.update(self._js.mine_params(script.get_text()))

        # From data-param-* / data-key / data-field attributes
        for tag in soup.find_all(True):
            if not isinstance(tag, Tag):
                continue
            for attr in tag.attrs:
                m = _DATA_PARAM_ATTR_RE.match(attr)
                if m and m.group(1):
                    mined.add(m.group(1).replace("-", "_").strip("_"))

        if not mined:
            return

        # Build a synthesised URL: existing params preserved, mined ones appended
        parsed = urlparse(page_url)
        existing = {k: v[0] for k, v in parse_qs(parsed.query, keep_blank_values=True).items()}
        combined = {**existing, **{p: "" for p in mined if p not in existing}}
        synth_url = parsed._replace(
            query=urlencode(sorted(combined.items()))
        ).geturl()

        fp = _param_fingerprint(synth_url)
        async with state.lock:
            if fp not in state.param_fps:
                state.param_fps.add(fp)
                state.result.urls_with_params.append(synth_url)
                logger.debug(
                    "Parameter mining: +%d param(s) from %s",
                    len(mined), page_url,
                )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _accept_url(self, url: str, base_origin: str) -> bool:
        """Return True if *url* should be added to the crawl queue."""
        if not url.startswith(("http://", "https://")):
            return False
        if not self._cfg.follow_external and _origin(url) != base_origin:
            return False
        return True
