"""
Integration tests — scanner against a live mock HTTP server.

The ``vuln_server`` fixture (defined in conftest.py) starts a real aiohttp
TestServer with deliberately vulnerable and safe endpoints.  Each test
performs a genuine HTTP scan using Scanner backed by a real HTTPClient.

Endpoint oracle (ground truth)
-------------------------------
Vulnerable : /vuln/html?q=   /vuln/attr?q=   /vuln/script?q=
             /vuln/multi?q=&name=  (both params)
             /vuln/form  (POST, field "query")
Safe       : /safe?q=   /static  (no params)

Accuracy metrics (TestAccuracyMetrics)
---------------------------------------
  reflection_accuracy = TP / (TP + FN)   — target ≥ 90 %
  false_positive_rate = FP / (FP + TN)   — target = 0 %
"""
from __future__ import annotations

import asyncio

import pytest
from aiohttp.test_utils import TestServer

from core.config import FrameworkConfig
from core.scanner import Scanner
from utils.http import HTTPClient


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_payloads() -> list[str]:
    return [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        '"><script>alert(1)</script>',
        "';alert(1)//",
    ]


async def _scan_url(url: str, config: FrameworkConfig, payloads: list[str]):
    async with HTTPClient(config.scanner) as http:
        scanner = Scanner(config, http)
        return await scanner.scan_url(url, payloads)


# ---------------------------------------------------------------------------
# Sanity-check the mock server itself
# ---------------------------------------------------------------------------


class TestMockServerEndpoints:
    async def test_vuln_html_returns_200(self, vuln_server: TestServer) -> None:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            resp = await session.get(vuln_server.make_url("/vuln/html?q=hello"))
            assert resp.status == 200

    async def test_safe_endpoint_does_not_reflect_input(
        self, vuln_server: TestServer
    ) -> None:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            resp = await session.get(vuln_server.make_url("/safe?q=UNIQUETOKEN"))
            text = await resp.text()
        # The safe endpoint never reflects user input back
        assert "UNIQUETOKEN" not in text

    async def test_vuln_html_reflects_raw_input(self, vuln_server: TestServer) -> None:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            resp = await session.get(vuln_server.make_url("/vuln/html?q=TESTTOKEN"))
            text = await resp.text()
        assert "TESTTOKEN" in text

    async def test_static_page_returns_no_params_url(self, vuln_server: TestServer) -> None:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            resp = await session.get(vuln_server.make_url("/static"))
            assert resp.status == 200


# ---------------------------------------------------------------------------
# Scanner detection tests
# ---------------------------------------------------------------------------


class TestScannerDetection:
    async def test_detects_html_text_context_xss(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings, "Expected finding on /vuln/html"
        assert result.findings[0].parameter == "q"

    async def test_detects_html_attribute_context_xss(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/attr?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings, "Expected finding on /vuln/attr"

    async def test_detects_script_context_xss(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/script?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings, "Expected finding on /vuln/script"

    async def test_no_false_positive_on_html_encoded_endpoint(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/safe?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert not result.findings, (
            f"False positive on safe endpoint: {result.findings}"
        )

    async def test_detects_both_params_on_multi_param_url(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/multi?q=a&name=b"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        found_params = {f.parameter for f in result.findings}
        assert "q"    in found_params, "Expected 'q' to be detected as vulnerable"
        assert "name" in found_params, "Expected 'name' to be detected as vulnerable"

    async def test_scanner_stops_after_first_hit_per_param(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        many_payloads = _minimal_payloads() * 25  # 100 payloads
        result = await _scan_url(url, test_config, many_payloads)
        assert len(result.findings) == 1, "Should emit exactly one finding per parameter"

    async def test_finding_has_non_empty_reflection_context(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings
        assert result.findings[0].reflection_context != ""

    async def test_finding_severity_is_valid(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings
        assert result.findings[0].severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}

    async def test_finding_has_encoding_metadata(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings
        f = result.findings[0]
        assert isinstance(f.encoding_types, tuple)
        assert isinstance(f.dangerous_chars_preserved, tuple)
        assert f.exploitation_difficulty != ""

    async def test_payloads_tested_counter_increments(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.payloads_tested >= 1

    async def test_parameters_tested_counter(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.parameters_tested == 1

    async def test_attack_url_contains_target_host(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings
        assert "127.0.0.1" in result.findings[0].attack_url

    async def test_evidence_is_non_empty(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.findings
        assert result.findings[0].evidence != ""


# ---------------------------------------------------------------------------
# Form scanning
# ---------------------------------------------------------------------------


class TestFormScanning:
    async def test_detects_post_form_injection(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        from core.crawler import Form, FormField
        form = Form(
            action=str(vuln_server.make_url("/vuln/form")),
            method="POST",
            fields=[FormField(name="query", input_type="text", value="")],
        )
        async with HTTPClient(test_config.scanner) as http:
            scanner = Scanner(test_config, http)
            result = await scanner.scan_form(form, _minimal_payloads())
        assert result.findings, "Expected finding on POST form"
        assert result.findings[0].parameter == "query"

    async def test_form_finding_has_evidence(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        from core.crawler import Form, FormField
        form = Form(
            action=str(vuln_server.make_url("/vuln/form")),
            method="POST",
            fields=[FormField(name="query", input_type="text", value="")],
        )
        async with HTTPClient(test_config.scanner) as http:
            scanner = Scanner(test_config, http)
            result = await scanner.scan_form(form, _minimal_payloads())
        assert result.findings
        assert result.findings[0].evidence != ""


# ---------------------------------------------------------------------------
# Accuracy metrics
# ---------------------------------------------------------------------------


class TestAccuracyMetrics:
    """
    Measure detection accuracy and false-positive rate against the known oracle.

    Oracle
    ------
    Vulnerable : /vuln/html, /vuln/attr, /vuln/script
    Safe       : /safe, /static (no query params → scanner returns 0 payloads_tested)

    Thresholds
    ----------
    reflection_accuracy ≥ 90 %
    false_positive_rate = 0 %
    """

    _ENDPOINTS: list[tuple[str, bool]] = [
        ("/vuln/html?q=probe",   True),
        ("/vuln/attr?q=probe",   True),
        ("/vuln/script?q=probe", True),
        ("/safe?q=probe",        False),
        ("/static",              False),
    ]

    async def test_reflection_accuracy_above_90_percent(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        payloads = _minimal_payloads()
        tp = fn = 0

        for path, is_vuln in self._ENDPOINTS:
            if not is_vuln:
                continue
            url = str(vuln_server.make_url(path))
            result = await _scan_url(url, test_config, payloads)
            if result.findings:
                tp += 1
            else:
                fn += 1

        total = tp + fn
        accuracy = tp / total if total else 1.0
        assert accuracy >= 0.90, (
            f"Reflection accuracy {accuracy:.0%} is below 90% threshold "
            f"(TP={tp}, FN={fn})"
        )

    async def test_false_positive_rate_is_zero(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        payloads = _minimal_payloads()
        fp = tn = 0

        for path, is_vuln in self._ENDPOINTS:
            if is_vuln:
                continue
            url = str(vuln_server.make_url(path))
            result = await _scan_url(url, test_config, payloads)
            if result.findings:
                fp += 1
            else:
                tn += 1

        total = fp + tn
        fp_rate = fp / total if total else 0.0
        assert fp_rate == 0.0, (
            f"False positive rate {fp_rate:.0%} > 0% on safe endpoints "
            f"(FP={fp}, TN={tn})"
        )

    async def test_scan_result_has_elapsed_time(
        self, vuln_server: TestServer, test_config: FrameworkConfig
    ) -> None:
        url = str(vuln_server.make_url("/vuln/html?q=test"))
        result = await _scan_url(url, test_config, _minimal_payloads())
        assert result.elapsed >= 0.0
