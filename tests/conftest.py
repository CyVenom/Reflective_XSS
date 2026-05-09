"""Shared pytest fixtures for the XSS framework test suite.

Provides:
  - vuln_server   : live aiohttp.TestServer with deliberately vulnerable/safe endpoints
  - test_config   : minimal FrameworkConfig for fast testing
  - finished_session, single_finding, minimal_result, empty_result : reporter fixtures
"""
from __future__ import annotations

from typing import AsyncGenerator

import pytest
import pytest_asyncio
from aiohttp import web
from aiohttp.test_utils import TestServer

from core.config import FrameworkConfig
from modules.base import ModuleResult
from reports.session import ScanSession


# ---------------------------------------------------------------------------
# Mock aiohttp application
# ---------------------------------------------------------------------------

def _build_vulnerable_app() -> web.Application:
    """Build an aiohttp app with known vulnerable and safe XSS endpoints."""

    async def html_text_vuln(req: web.Request) -> web.Response:
        q = req.rel_url.query.get("q", "")
        return web.Response(
            text=f"<html><body><p>Results for: {q}</p></body></html>",
            content_type="text/html",
        )

    async def html_attr_vuln(req: web.Request) -> web.Response:
        q = req.rel_url.query.get("q", "")
        return web.Response(
            text=f'<html><body><input value="{q}"></body></html>',
            content_type="text/html",
        )

    async def script_context_vuln(req: web.Request) -> web.Response:
        q = req.rel_url.query.get("q", "")
        return web.Response(
            text=f"<html><body><script>var q = '{q}';</script></body></html>",
            content_type="text/html",
        )

    async def safe_encoded(req: web.Request) -> web.Response:
        # Accept the parameter but never reflect any user input back —
        # this is the definitive "safe" endpoint for false-positive testing.
        return web.Response(
            text="<html><body><p>Your query was processed safely.</p></body></html>",
            content_type="text/html",
        )

    async def multi_param_vuln(req: web.Request) -> web.Response:
        q    = req.rel_url.query.get("q", "")
        name = req.rel_url.query.get("name", "")
        return web.Response(
            text=f"<html><body><p>{q}</p><p>{name}</p></body></html>",
            content_type="text/html",
        )

    async def form_page(req: web.Request) -> web.Response:
        return web.Response(
            text=(
                "<html><body>"
                '<form action="/vuln/form" method="post">'
                '<input name="query" type="text">'
                '<input type="submit" value="Search">'
                "</form></body></html>"
            ),
            content_type="text/html",
        )

    async def form_post(req: web.Request) -> web.Response:
        if req.method == "POST":
            data = await req.post()
            q = data.get("query", "")
        else:
            q = req.rel_url.query.get("query", "")
        return web.Response(
            text=f"<html><body><p>{q}</p></body></html>",
            content_type="text/html",
        )

    async def static_page(req: web.Request) -> web.Response:
        return web.Response(
            text="<html><body>Static content only.</body></html>",
            content_type="text/html",
        )

    app = web.Application()
    app.router.add_get("/vuln/html",   html_text_vuln)
    app.router.add_get("/vuln/attr",   html_attr_vuln)
    app.router.add_get("/vuln/script", script_context_vuln)
    app.router.add_get("/safe",        safe_encoded)
    app.router.add_get("/vuln/multi",  multi_param_vuln)
    app.router.add_get("/vuln/form",   form_page)
    app.router.add_post("/vuln/form",  form_post)
    app.router.add_get("/static",      static_page)
    return app


# ---------------------------------------------------------------------------
# Server fixture
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def vuln_server() -> AsyncGenerator[TestServer, None]:
    """Start a real aiohttp test server; teardown after each test."""
    server = TestServer(_build_vulnerable_app())
    await server.start_server()
    yield server
    await server.close()


# ---------------------------------------------------------------------------
# Config fixture
# ---------------------------------------------------------------------------

@pytest.fixture
def test_config() -> FrameworkConfig:
    cfg = FrameworkConfig.default()
    cfg.scanner.concurrency = 5
    cfg.scanner.timeout     = 5.0
    cfg.scanner.max_retries = 0
    cfg.scanner.verify_ssl  = False
    return cfg


# ---------------------------------------------------------------------------
# Reporter fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def finished_session() -> ScanSession:
    s = ScanSession.start(scan_options={"target": "http://test.local/?q=x", "forms": False})
    s.finish()
    return s


@pytest.fixture
def single_finding() -> dict:
    return {
        "type":                      "Reflected XSS",
        "severity":                  "HIGH",
        "severity_score":            7.5,
        "confidence":                3,
        "confidence_label":          "HIGH",
        "parameter":                 "q",
        "payload":                   "<script>alert(XYZMARKER)</script>",
        "attack_url":                "http://test.local/?q=%3Cscript%3E",
        "evidence":                  "<p><script>alert(XYZMARKER)</script></p>",
        "reflection_context":        "HTML_TEXT",
        "exploitation_notes":        "Direct injection into HTML text node.",
        "encoding_types":            ["none"],
        "dangerous_chars_preserved": ["<", ">", "(", ")"],
        "exploitation_difficulty":   "TRIVIAL",
    }


@pytest.fixture
def minimal_result(finished_session: ScanSession, single_finding: dict) -> ModuleResult:
    return ModuleResult(
        module_name="reflected-xss",
        target="http://test.local/?q=x",
        findings=[single_finding],
        errors=[],
        metadata={
            "payloads_tested":   50,
            "parameters_tested": 1,
            "payloads_loaded":   50,
            "session":           finished_session.to_dict(),
        },
    )


@pytest.fixture
def empty_result() -> ModuleResult:
    return ModuleResult(
        module_name="reflected-xss",
        target="http://test.local/safe",
        findings=[],
        errors=[],
        metadata={"payloads_tested": 30, "parameters_tested": 1, "payloads_loaded": 30},
    )
