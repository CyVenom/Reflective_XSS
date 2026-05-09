"""Tests for core/crawler.py — high-performance async crawler."""

from __future__ import annotations

import asyncio
from typing import Optional
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest

from core.config import CrawlerConfig
from core.crawler import (
    Crawler,
    CrawlResult,
    Form,
    FormField,
    JavaScriptEndpoint,
    _DomainRateLimiter,
    _JSExtractor,
    _RobotsCache,
    _normalize_url,
    _param_fingerprint,
    _should_skip,
)
from utils.http import HTTPClient, HTTPResponse


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MARKER = "AbCdEfGh"


def _resp(text: str, url: str = "http://example.com/", status: int = 200,
          ct: str = "text/html") -> HTTPResponse:
    return HTTPResponse(
        status=status, text=text,
        headers={"Content-Type": ct}, url=url,
    )


def _html(body: str) -> str:
    return f"<html><body>{body}</body></html>"


def _make_http(responses: dict[str, Optional[HTTPResponse]]) -> HTTPClient:
    """Build a mock HTTPClient that returns canned responses keyed by URL prefix.
    Longest matching prefix wins, so /app.js doesn't accidentally match /."""
    http = MagicMock(spec=HTTPClient)
    # Sort descending by key length so longest prefix always wins
    sorted_responses = sorted(responses.items(), key=lambda kv: len(kv[0]), reverse=True)

    async def fake_get(url: str, **_kw) -> Optional[HTTPResponse]:
        for prefix, resp in sorted_responses:
            if url.startswith(prefix):
                return resp
        return None

    http.get = fake_get
    return http


def _config(**kwargs) -> CrawlerConfig:
    defaults = dict(
        max_depth=2, max_pages=20, concurrency=2,
        rate_limit=0, respect_robots=False,
        js_extraction=True, parameter_mining=True,
        follow_external=False,
    )
    defaults.update(kwargs)
    return CrawlerConfig(**defaults)


# ---------------------------------------------------------------------------
# URL normalisation
# ---------------------------------------------------------------------------


class TestNormalizeUrl:
    def test_strips_fragment(self):
        assert _normalize_url("http://x.com/p#section") == "http://x.com/p"

    def test_lowercases_scheme_and_host(self):
        assert _normalize_url("HTTP://X.COM/p") == "http://x.com/p"

    def test_removes_default_http_port(self):
        assert _normalize_url("http://x.com:80/p") == "http://x.com/p"

    def test_removes_default_https_port(self):
        assert _normalize_url("https://x.com:443/p") == "https://x.com/p"

    def test_keeps_non_default_port(self):
        result = _normalize_url("http://x.com:8080/p")
        assert "8080" in result

    def test_strips_utm_params(self):
        url = "http://x.com/?q=1&utm_source=google&utm_medium=cpc"
        norm = _normalize_url(url)
        assert "utm_source" not in norm
        assert "q=1" in norm

    def test_strips_fbclid(self):
        url = "http://x.com/?q=1&fbclid=abc123"
        assert "fbclid" not in _normalize_url(url)

    def test_sorts_query_params(self):
        a = _normalize_url("http://x.com/?z=1&a=2")
        b = _normalize_url("http://x.com/?a=2&z=1")
        assert a == b

    def test_strips_trailing_slash(self):
        assert _normalize_url("http://x.com/path/") == "http://x.com/path"

    def test_root_path_preserved(self):
        assert _normalize_url("http://x.com/") == "http://x.com/"


class TestParamFingerprint:
    def test_same_keys_different_values(self):
        a = _param_fingerprint("http://x.com/?id=1&name=alice")
        b = _param_fingerprint("http://x.com/?id=99&name=bob")
        assert a == b

    def test_different_keys_differ(self):
        a = _param_fingerprint("http://x.com/?id=1")
        b = _param_fingerprint("http://x.com/?token=1")
        assert a != b

    def test_keys_sorted(self):
        a = _param_fingerprint("http://x.com/?z=1&a=2")
        b = _param_fingerprint("http://x.com/?a=1&z=2")
        assert a == b


class TestShouldSkip:
    def test_skips_image(self):
        assert _should_skip("http://x.com/img/logo.png")

    def test_skips_css(self):
        assert _should_skip("http://x.com/style.css")

    def test_skips_pdf(self):
        assert _should_skip("http://x.com/doc.pdf")

    def test_skips_non_http_scheme(self):
        assert _should_skip("ftp://x.com/file")
        assert _should_skip("mailto:x@x.com")

    def test_allows_html_url(self):
        assert not _should_skip("http://x.com/page.html")

    def test_allows_no_extension(self):
        assert not _should_skip("http://x.com/search?q=1")

    def test_skips_source_map(self):
        assert _should_skip("http://x.com/app.js.map")


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class TestDomainRateLimiter:
    def test_zero_rate_never_sleeps(self):
        limiter = _DomainRateLimiter(rate=0)

        async def run():
            t0 = asyncio.get_event_loop().time()
            for _ in range(5):
                await limiter.acquire("example.com")
            return asyncio.get_event_loop().time() - t0

        elapsed = asyncio.get_event_loop().run_until_complete(run())
        assert elapsed < 0.05  # near-zero

    def test_rate_limits_sequential_requests(self):
        limiter = _DomainRateLimiter(rate=100)  # 100 req/s → 10ms gap

        async def run():
            import time
            t0 = time.monotonic()
            for _ in range(3):
                await limiter.acquire("example.com")
            return time.monotonic() - t0

        elapsed = asyncio.get_event_loop().run_until_complete(run())
        # 3 requests at 100 req/s → ~20ms minimum (2 intervals after first)
        assert elapsed >= 0.015

    def test_different_domains_independent(self):
        limiter = _DomainRateLimiter(rate=10)

        async def run():
            import time
            t0 = time.monotonic()
            await limiter.acquire("a.com")
            await limiter.acquire("b.com")
            return time.monotonic() - t0

        elapsed = asyncio.get_event_loop().run_until_complete(run())
        # Two different domains → no enforced gap between them
        assert elapsed < 0.05


# ---------------------------------------------------------------------------
# robots.txt cache
# ---------------------------------------------------------------------------


class TestRobotsCache:
    def test_allows_when_no_robots_txt(self):
        http = _make_http({"http://x.com/robots.txt": _resp("", status=404)})
        cache = _RobotsCache(http, "TestBot")

        async def run():
            return await cache.allowed("http://x.com/page")

        assert asyncio.get_event_loop().run_until_complete(run()) is True

    def test_respects_disallow(self):
        robots = _resp("User-agent: *\nDisallow: /private/\n",
                       url="http://x.com/robots.txt", ct="text/plain")
        http = _make_http({"http://x.com/robots.txt": robots})
        cache = _RobotsCache(http, "*")

        async def run():
            return await cache.allowed("http://x.com/private/secret")

        assert asyncio.get_event_loop().run_until_complete(run()) is False

    def test_allows_unlisted_path(self):
        robots = _resp("User-agent: *\nDisallow: /private/\n",
                       url="http://x.com/robots.txt", ct="text/plain")
        http = _make_http({"http://x.com/robots.txt": robots})
        cache = _RobotsCache(http, "*")

        async def run():
            return await cache.allowed("http://x.com/public/page")

        assert asyncio.get_event_loop().run_until_complete(run()) is True

    def test_cached_after_first_fetch(self):
        call_count = 0
        robots_text = "User-agent: *\nDisallow:\n"

        async def fake_get(url, **_):
            nonlocal call_count
            call_count += 1
            return _resp(robots_text, ct="text/plain")

        http = MagicMock(spec=HTTPClient)
        http.get = fake_get
        cache = _RobotsCache(http, "*")

        async def run():
            await cache.allowed("http://x.com/a")
            await cache.allowed("http://x.com/b")

        asyncio.get_event_loop().run_until_complete(run())
        assert call_count == 1  # only fetched once


# ---------------------------------------------------------------------------
# JS extractor
# ---------------------------------------------------------------------------


class TestJSExtractor:
    def setup_method(self):
        self.ext = _JSExtractor()

    def test_fetch_call_extracted(self):
        js = "fetch('/api/search?q=1').then(r => r.json())"
        results = self.ext.extract_endpoints(js, "http://x.com/")
        urls = [r[0] for r in results]
        assert any("/api/search" in u for u in urls)

    def test_axios_call_extracted(self):
        js = "axios.get('/api/users?page=1')"
        results = self.ext.extract_endpoints(js, "http://x.com/")
        urls = [r[0] for r in results]
        assert any("/api/users" in u for u in urls)

    def test_api_path_literal_extracted(self):
        js = "const EP = '/api/v2/data?format=json';"
        results = self.ext.extract_endpoints(js, "http://x.com/")
        urls = [r[0] for r in results]
        assert any("format=json" in u for u in urls)

    def test_no_query_string_not_extracted(self):
        js = "fetch('/api/no-params')"
        results = self.ext.extract_endpoints(js, "http://x.com/")
        assert results == []

    def test_absolute_url_preserved(self):
        js = "fetch('https://api.example.com/v1/search?q=test')"
        results = self.ext.extract_endpoints(js, "http://x.com/")
        urls = [r[0] for r in results]
        assert any("api.example.com" in u for u in urls)

    def test_relative_path_without_slash_skipped(self):
        js = "fetch('some/relative/path?q=1')"
        results = self.ext.extract_endpoints(js, "http://x.com/")
        assert results == []

    def test_url_search_params_mined(self):
        js = "new URLSearchParams({'query': q, 'page': p, 'limit': 10})"
        params = self.ext.mine_params(js)
        assert "query" in params
        assert "page" in params
        assert "limit" in params

    def test_json_block_params_extracted(self):
        html = '<script type="application/json">{"user_id": 1, "token": "x"}</script>'
        params = self.ext.extract_json_block_params(html)
        assert "user_id" in params
        assert "token" in params

    def test_duplicate_endpoints_deduplicated(self):
        js = "fetch('/api/v1?q=1'); fetch('/api/v1?q=2');"
        results = self.ext.extract_endpoints(js, "http://x.com/")
        urls = [r[0] for r in results]
        assert len([u for u in urls if "/api/v1" in u]) == 1


# ---------------------------------------------------------------------------
# Crawler integration (mocked HTTP)
# ---------------------------------------------------------------------------


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


class TestCrawlerBasic:
    def test_visits_start_url(self):
        http = _make_http({"http://x.com/": _resp(_html("hello"))})
        crawler = Crawler(_config(), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert any("x.com" in v for v in result.visited)

    def test_records_parameterised_url(self):
        http = _make_http({"http://x.com/": _resp(_html(""), url="http://x.com/?q=test")})
        crawler = Crawler(_config(), http)
        result = _run(crawler.crawl("http://x.com/?q=test"))
        assert result.urls_with_params

    def test_no_response_added_to_errors(self):
        http = _make_http({})  # no responses
        crawler = Crawler(_config(), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert result.errors

    def test_follows_links_within_depth(self):
        pages = {
            "http://x.com/": _resp(_html('<a href="/page?id=1">link</a>')),
            "http://x.com/page": _resp(_html("page content")),
        }
        http = _make_http(pages)
        crawler = Crawler(_config(max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert any("/page" in v for v in result.visited)

    def test_discovers_child_param_url(self):
        pages = {
            "http://x.com/": _resp(_html('<a href="/search?q=xss">search</a>')),
            "http://x.com/search": _resp(_html("results")),
        }
        http = _make_http(pages)
        crawler = Crawler(_config(max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert any("search" in u and "q=" in u for u in result.urls_with_params)

    def test_does_not_follow_external_by_default(self):
        html = _html('<a href="http://evil.com/?x=1">out</a>')
        http = _make_http({
            "http://x.com/": _resp(html),
            "http://evil.com/": _resp(_html("evil")),
        })
        crawler = Crawler(_config(follow_external=False, max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert not any("evil.com" in v for v in result.visited)

    def test_follows_external_when_enabled(self):
        html = _html('<a href="http://other.com/?x=1">out</a>')
        http = _make_http({
            "http://x.com/": _resp(html),
            "http://other.com/": _resp(_html("other")),
        })
        crawler = Crawler(_config(follow_external=True, max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert any("other.com" in v for v in result.visited)

    def test_max_pages_respected(self):
        many_links = "".join(f'<a href="/p{i}?id={i}">l</a>' for i in range(20))
        pages = {"http://x.com/": _resp(_html(many_links))}
        for i in range(20):
            pages[f"http://x.com/p{i}"] = _resp(_html("page"))
        http = _make_http(pages)
        crawler = Crawler(_config(max_pages=3, max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert len(result.visited) <= 3

    def test_skips_image_links(self):
        html = _html('<a href="/photo.png">img</a><a href="/page?id=1">page</a>')
        http = _make_http({
            "http://x.com/": _resp(html),
            "http://x.com/page": _resp(_html("page")),
        })
        crawler = Crawler(_config(max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert not any("photo.png" in v for v in result.visited)

    def test_deduplicates_structurally_identical_urls(self):
        html = _html('<a href="/s?q=hello">a</a><a href="/s?q=world">b</a>')
        http = _make_http({
            "http://x.com/": _resp(html),
            "http://x.com/s": _resp(_html("results")),
        })
        crawler = Crawler(_config(max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        # Same path + param names → only one entry in urls_with_params
        matching = [u for u in result.urls_with_params if "/s" in u]
        assert len(matching) == 1


class TestCrawlerForms:
    def test_extracts_get_form(self):
        html = _html('<form action="/search" method="get"><input name="q"></form>')
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert result.forms
        form = result.forms[0]
        assert form.method == "GET"
        assert any(f.name == "q" for f in form.fields)

    def test_extracts_post_form(self):
        html = _html(
            '<form action="/login" method="post">'
            '<input name="user"><input name="pass" type="password">'
            '</form>'
        )
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert result.forms
        form = result.forms[0]
        assert form.method == "POST"
        field_names = {f.name for f in form.fields}
        assert {"user", "pass"} == field_names

    def test_injectable_fields_excludes_hidden(self):
        html = _html(
            '<form action="/submit" method="post">'
            '<input name="csrf" type="hidden" value="tok">'
            '<input name="query">'
            '</form>'
        )
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(), http)
        result = _run(crawler.crawl("http://x.com/"))
        injectable = result.forms[0].injectable_fields()
        assert all(f.name != "csrf" for f in injectable)
        assert any(f.name == "query" for f in injectable)

    def test_form_action_relative_resolved(self):
        html = _html('<form action="search?q=1"><input name="q"></form>')
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert result.forms[0].action.startswith("http://x.com")


class TestCrawlerJSExtraction:
    def test_js_endpoint_extracted_from_inline_script(self):
        html = _html(
            "<script>fetch('/api/search?q=test').then(r=>r.json())</script>"
        )
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(js_extraction=True), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert result.js_endpoints
        assert any("api/search" in ep.url for ep in result.js_endpoints)

    def test_js_extraction_disabled(self):
        html = _html(
            "<script>fetch('/api/search?q=test').then(r=>r.json())</script>"
        )
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(js_extraction=False), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert result.js_endpoints == []

    def test_standalone_js_file_processed(self):
        html = _html('<script src="/app.js"></script>')
        js_resp = _resp(
            "fetch('/api/data?format=json')",
            url="http://x.com/app.js",
            ct="application/javascript",
        )
        http = _make_http({
            "http://x.com/": _resp(html),
            "http://x.com/app.js": js_resp,
        })
        crawler = Crawler(_config(js_extraction=True, max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert any("api/data" in ep.url for ep in result.js_endpoints)

    def test_js_endpoint_source_page_recorded(self):
        html = _html("<script>fetch('/api/items?page=1')</script>")
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(js_extraction=True), http)
        result = _run(crawler.crawl("http://x.com/"))
        ep = next((e for e in result.js_endpoints if "items" in e.url), None)
        assert ep is not None
        assert "x.com" in ep.source_page

    def test_all_scan_urls_includes_js_endpoints(self):
        html = _html("<script>fetch('/api/search?q=1')</script>")
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(js_extraction=True), http)
        result = _run(crawler.crawl("http://x.com/"))
        scan_urls = result.all_scan_urls
        assert any("api/search" in u for u in scan_urls)


class TestCrawlerParameterMining:
    def test_input_names_mined(self):
        html = _html(
            '<form action="/"><input name="username"><input name="token"></form>'
        )
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(parameter_mining=True), http)
        result = _run(crawler.crawl("http://x.com/"))
        combined = " ".join(result.urls_with_params)
        assert "username" in combined or result.forms

    def test_param_mining_disabled(self):
        html = _html('<input name="secret_key">')
        http = _make_http({"http://x.com/": _resp(html)})
        crawler = Crawler(_config(parameter_mining=False), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert all("secret_key" not in u for u in result.urls_with_params)

    def test_url_search_params_mined_from_script(self):
        html = _html(
            "<script>new URLSearchParams({'search_term': v, 'category': c})</script>"
        )
        http = _make_http({"http://x.com/?q=1": _resp(html, url="http://x.com/?q=1")})
        crawler = Crawler(_config(parameter_mining=True), http)
        result = _run(crawler.crawl("http://x.com/?q=1"))
        combined = " ".join(result.urls_with_params)
        assert "search_term" in combined or "category" in combined


class TestCrawlerRobots:
    def test_robots_disallow_respected(self):
        robots = _resp("User-agent: *\nDisallow: /admin/\n",
                       url="http://x.com/robots.txt", ct="text/plain")
        pages = {
            "http://x.com/robots.txt": robots,
            "http://x.com/": _resp(_html('<a href="/admin/page?id=1">admin</a>')),
            "http://x.com/admin/": _resp(_html("admin")),
        }
        http = _make_http(pages)
        crawler = Crawler(_config(respect_robots=True, max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert not any("admin" in v for v in result.visited)

    def test_robots_disabled_visits_all(self):
        robots = _resp("User-agent: *\nDisallow: /\n",
                       url="http://x.com/robots.txt", ct="text/plain")
        pages = {
            "http://x.com/robots.txt": robots,
            "http://x.com/": _resp(_html('<a href="/page?id=1">link</a>')),
            "http://x.com/page": _resp(_html("page")),
        }
        http = _make_http(pages)
        crawler = Crawler(_config(respect_robots=False, max_depth=1), http)
        result = _run(crawler.crawl("http://x.com/"))
        assert any("/page" in v for v in result.visited)


class TestCrawlResult:
    def test_all_scan_urls_deduplicates(self):
        r = CrawlResult(base_url="http://x.com/")
        r.urls_with_params = ["http://x.com/?q=1", "http://x.com/?q=1"]
        r.js_endpoints = [JavaScriptEndpoint(url="http://x.com/?q=1", source_page="http://x.com/")]
        assert len(r.all_scan_urls) == 1

    def test_all_scan_urls_merges_js_endpoints(self):
        r = CrawlResult(base_url="http://x.com/")
        r.urls_with_params = ["http://x.com/?q=1"]
        r.js_endpoints = [
            JavaScriptEndpoint(url="http://x.com/api?format=json", source_page="http://x.com/")
        ]
        urls = r.all_scan_urls
        assert len(urls) == 2

    def test_js_endpoint_without_params_excluded_from_scan_urls(self):
        r = CrawlResult(base_url="http://x.com/")
        r.js_endpoints = [
            JavaScriptEndpoint(url="http://x.com/api/no-params", source_page="http://x.com/")
        ]
        assert r.all_scan_urls == []

    def test_form_injectable_fields_filters_submit(self):
        form = Form(action="/s", method="POST", fields=[
            FormField(name="query", input_type="text"),
            FormField(name="go", input_type="submit"),
        ])
        injectable = form.injectable_fields()
        assert len(injectable) == 1
        assert injectable[0].name == "query"
