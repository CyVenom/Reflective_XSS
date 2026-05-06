"""Unit tests for the async scanner engine."""

from __future__ import annotations

import re
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import pytest

from core.config import FrameworkConfig
from core.scanner import Finding, Scanner, ScanResult
from utils.http import HTTPClient, HTTPResponse


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> FrameworkConfig:
    cfg = FrameworkConfig.default()
    cfg.scanner.concurrency = 2  # keep tests predictable
    return cfg


def _make_reflective_http() -> HTTPClient:
    """
    Return a mock HTTPClient whose GET handler reflects the marker embedded
    in the URL's query parameter value back into the response body.
    """

    async def _get(url: str, **kwargs: Any) -> HTTPResponse:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        # Extract the first 8-char alphabetic run (the marker) from any param
        value = next(iter(qs.values()), [""])[0]
        match = re.search(r"[A-Za-z]{8}", value)
        marker = match.group(0) if match else ""
        body = f"<html><body>You searched: {marker}</body></html>"
        return HTTPResponse(status=200, text=body, headers={}, url=url)

    http = MagicMock(spec=HTTPClient)
    http.get = AsyncMock(side_effect=_get)
    return http


def _make_non_reflective_http() -> HTTPClient:
    async def _get(url: str, **kwargs: Any) -> HTTPResponse:
        return HTTPResponse(
            status=200, text="<html><body>Safe static page</body></html>",
            headers={}, url=url,
        )

    http = MagicMock(spec=HTTPClient)
    http.get = AsyncMock(side_effect=_get)
    return http


def _make_failing_http() -> HTTPClient:
    http = MagicMock(spec=HTTPClient)
    http.get = AsyncMock(return_value=None)
    return http


# ---------------------------------------------------------------------------
# ScanResult model
# ---------------------------------------------------------------------------


class TestScanResult:
    def test_vulnerable_property_true(self) -> None:
        r = ScanResult(target_url="https://example.com")
        r.findings.append(
            Finding("https://example.com", "q", "<payload>", "https://example.com?q=x", "", "HIGH")
        )
        assert r.vulnerable is True

    def test_vulnerable_property_false(self) -> None:
        r = ScanResult(target_url="https://example.com")
        assert r.vulnerable is False


# ---------------------------------------------------------------------------
# Scanner.scan_url
# ---------------------------------------------------------------------------


class TestScanUrl:
    @pytest.mark.asyncio
    async def test_no_params_returns_empty(self, config: FrameworkConfig) -> None:
        scanner = Scanner(config, _make_non_reflective_http())
        result = await scanner.scan_url("https://example.com/page", ["<script>alert(1)</script>"])
        assert result.findings == []
        assert result.payloads_tested == 0

    @pytest.mark.asyncio
    async def test_detects_reflection(self, config: FrameworkConfig) -> None:
        scanner = Scanner(config, _make_reflective_http())
        result = await scanner.scan_url(
            "https://example.com/search?q=hello",
            ["<script>alert(1)</script>"],
        )
        assert result.findings, "Expected at least one finding"
        assert result.findings[0].parameter == "q"
        assert result.payloads_tested >= 1

    @pytest.mark.asyncio
    async def test_no_finding_without_reflection(self, config: FrameworkConfig) -> None:
        scanner = Scanner(config, _make_non_reflective_http())
        result = await scanner.scan_url(
            "https://example.com/page?id=1",
            ["<script>alert(1)</script>"],
        )
        assert result.findings == []

    @pytest.mark.asyncio
    async def test_stops_after_first_hit_per_param(self, config: FrameworkConfig) -> None:
        """Scanner must not continue testing more payloads once a param is confirmed."""
        http = _make_reflective_http()
        payloads = ["<script>alert(1)</script>"] * 10  # 10 identical payloads
        scanner = Scanner(config, http)
        result = await scanner.scan_url("https://example.com/?q=x", payloads)
        # Only one finding per parameter
        assert len(result.findings) == 1
        # And only one request was made (stopped after first hit)
        assert result.payloads_tested == 1

    @pytest.mark.asyncio
    async def test_records_error_on_failed_request(self, config: FrameworkConfig) -> None:
        scanner = Scanner(config, _make_failing_http())
        result = await scanner.scan_url(
            "https://example.com/?q=x",
            ["<script>alert(1)</script>"],
        )
        assert result.findings == []
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_multiple_params_tested(self, config: FrameworkConfig) -> None:
        scanner = Scanner(config, _make_reflective_http())
        result = await scanner.scan_url(
            "https://example.com/search?q=hello&page=1",
            ["<script>alert(1)</script>"],
        )
        assert result.parameters_tested == 2


# ---------------------------------------------------------------------------
# Scanner.scan_form
# ---------------------------------------------------------------------------


class TestScanForm:
    @pytest.mark.asyncio
    async def test_no_injectable_fields_returns_empty(
        self, config: FrameworkConfig
    ) -> None:
        from core.crawler import Form, FormField

        form = Form(
            action="https://example.com/submit",
            method="POST",
            fields=[
                FormField("_token", "hidden", "abc123"),
                FormField("submit_btn", "submit", ""),
            ],
        )
        scanner = Scanner(config, _make_reflective_http())
        result = await scanner.scan_form(form, ["<script>alert(1)</script>"])
        assert result.findings == []
        assert result.parameters_tested == 0

    @pytest.mark.asyncio
    async def test_post_form_tested(self, config: FrameworkConfig) -> None:
        from core.crawler import Form, FormField

        async def _post(url: str, data: dict, **kwargs: Any) -> HTTPResponse:
            value = next(iter(data.values()), "")
            match = re.search(r"[A-Za-z]{8}", value)
            marker = match.group(0) if match else ""
            return HTTPResponse(
                status=200,
                text=f"<html><body>Hello {marker}</body></html>",
                headers={},
                url=url,
            )

        http = MagicMock(spec=HTTPClient)
        http.post = AsyncMock(side_effect=_post)

        form = Form(
            action="https://example.com/comment",
            method="POST",
            fields=[FormField("comment", "text", "")],
        )
        scanner = Scanner(config, http)
        result = await scanner.scan_form(form, ["<script>alert(1)</script>"])
        assert result.findings, "Expected a finding in POST form"
        assert result.findings[0].parameter == "comment"
