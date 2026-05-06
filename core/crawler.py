"""
Async web crawler for discovering parameterised URLs and HTML forms.

The crawler performs a breadth-first traversal of a target web application,
collecting every URL that contains a query string (potential injection point)
and every HTML form (GET or POST).  Results are passed directly to the
scanning engine for payload injection.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from core.config import CrawlerConfig
from utils.http import HTTPClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FormField:
    """Represents a single input within an HTML form."""

    name: str
    input_type: str = "text"
    value: str = ""


@dataclass
class Form:
    """Represents a discovered HTML form and its injectable fields."""

    action: str
    method: str  # "GET" or "POST"
    fields: list[FormField] = field(default_factory=list)

    def injectable_fields(self) -> list[FormField]:
        """Return only fields that can carry arbitrary user input."""
        skip = {"hidden", "submit", "button", "image", "reset", "file"}
        return [f for f in self.fields if f.input_type.lower() not in skip]


@dataclass
class CrawlResult:
    """Aggregate of everything the crawler discovered."""

    base_url: str
    urls_with_params: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    visited: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# Crawler
# ---------------------------------------------------------------------------


class Crawler:
    """
    Breadth-first async crawler bounded by depth and page-count limits.

    Only the origin of the start URL is crawled by default; set
    ``CrawlerConfig.follow_external = True`` to cross origins.
    """

    def __init__(self, config: CrawlerConfig, http_client: HTTPClient) -> None:
        self._config = config
        self._http = http_client

    async def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl *start_url* and return all discovered injection points.

        Args:
            start_url: The seed URL; the crawl stays within its origin unless
                       ``follow_external`` is enabled.

        Returns:
            A :class:`CrawlResult` ready for the scanning engine.
        """
        result = CrawlResult(base_url=start_url)
        base_origin = _origin(start_url)

        # BFS queue: (url, depth)
        queue: asyncio.Queue[tuple[str, int]] = asyncio.Queue()
        await queue.put((start_url, 0))

        while not queue.empty() and len(result.visited) < self._config.max_pages:
            url, depth = await queue.get()

            if url in result.visited or depth > self._config.max_depth:
                continue
            result.visited.add(url)

            response = await self._http.get(url)
            if response is None:
                logger.debug("Skipping unreachable URL: %s", url)
                continue

            # Collect parameterised URLs
            if urlparse(url).query:
                result.urls_with_params.append(url)

            soup = BeautifulSoup(response.text, "html.parser")
            result.forms.extend(self._extract_forms(soup, url))

            if depth < self._config.max_depth:
                for link in self._extract_links(soup, url, base_origin):
                    if link not in result.visited:
                        await queue.put((link, depth + 1))

        logger.info(
            "Crawl finished: %d pages, %d parameterised URLs, %d forms",
            len(result.visited),
            len(result.urls_with_params),
            len(result.forms),
        )
        return result

    def _extract_links(
        self, soup: BeautifulSoup, base_url: str, base_origin: str
    ) -> list[str]:
        """Return absolute, same-origin (or external if configured) href links."""
        links: list[str] = []
        for tag in soup.find_all("a", href=True):
            href: str = tag["href"]
            absolute = urljoin(base_url, href).split("#")[0]  # strip fragments
            if not absolute.startswith(("http://", "https://")):
                continue
            if not self._config.follow_external and _origin(absolute) != base_origin:
                continue
            links.append(absolute)
        return links

    def _extract_forms(self, soup: BeautifulSoup, page_url: str) -> list[Form]:
        """Parse all ``<form>`` elements on a page into :class:`Form` objects."""
        forms: list[Form] = []
        for form_tag in soup.find_all("form"):
            action = urljoin(page_url, form_tag.get("action") or page_url)
            method = (form_tag.get("method") or "get").strip().upper()

            fields: list[FormField] = []
            for inp in form_tag.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if not name:
                    continue
                fields.append(
                    FormField(
                        name=name,
                        input_type=(inp.get("type") or "text").lower(),
                        value=inp.get("value") or "",
                    )
                )

            if fields:
                forms.append(Form(action=action, method=method, fields=fields))
        return forms


# ---------------------------------------------------------------------------
# Module-level helper
# ---------------------------------------------------------------------------


def _origin(url: str) -> str:
    """Return ``scheme://host:port`` for *url*."""
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
