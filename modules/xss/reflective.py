"""
Reflected XSS vulnerability module.

This is the primary module shipped with the framework.  It tests URL query
parameters and HTML form fields for reflected cross-site scripting by injecting
uniquely-marked payloads and analysing HTTP responses with
:class:`~core.reflection.ReflectionAnalyzer`.

Optional crawling discovers additional injection points beyond the seed URL.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

from bs4 import BeautifulSoup

from core.config import FrameworkConfig
from core.crawler import Crawler
from core.reflection import ConfidenceLevel
from core.scanner import Scanner, ScanResult
from modules.base import BaseModule, ModuleResult
from payloads.engine import PayloadEngine
from utils.helpers import extract_params, normalize_url
from utils.http import HTTPClient

try:
    from core.browser import BrowserConfirmer
    _BROWSER_AVAILABLE = True
except ImportError:
    _BROWSER_AVAILABLE = False

# Context-specific severity multipliers (most dangerous context = 1.0)
_CONTEXT_SCORE_FACTOR: dict[str, float] = {
    "SCRIPT_BLOCK":           1.00,
    "HTML_ATTRIBUTE_EVENT":   1.00,
    "SCRIPT_STRING":          0.90,
    "HTML_ATTRIBUTE_URL":     0.85,
    "HTML_TEXT":              0.80,
    "HTML_ATTRIBUTE":         0.70,
    "STYLE_BLOCK":            0.60,
    "META_TAG":               0.50,
    "HTML_COMMENT":           0.40,
    "UNKNOWN":                0.60,
}


def _severity_score(confidence: ConfidenceLevel, context: str) -> float:
    """Compute a 0-10 severity score from confidence level and reflection context."""
    base   = confidence.value * 2.5  # 2.5 / 5.0 / 7.5 / 10.0
    factor = _CONTEXT_SCORE_FACTOR.get(context, 0.60)
    return round(base * factor, 1)

logger = logging.getLogger(__name__)


class ReflectiveXSSModule(BaseModule):
    """
    Module for detecting Reflected Cross-Site Scripting (rXSS).

    Supports:

    - URL query parameter scanning
    - HTML form field scanning (GET and POST)
    - Optional site crawling to discover additional injection points
    - Custom or bundled payload sets
    - WAF-bypass payload variants (opt-in via config)

    The module returns a :class:`~modules.base.ModuleResult` whose ``findings``
    list follows this schema per entry:

    .. code-block:: python

        {
            "type":               str,   # "Reflected XSS"
            "severity":          str,   # "HIGH"
            "parameter":         str,   # vulnerable param name
            "payload":           str,   # exact marked payload used
            "attack_url":        str,   # reproducible PoC URL
            "evidence":          str,   # response excerpt
            "reflection_context": str,  # e.g. "SCRIPT_BLOCK"
        }
    """

    name = "reflected-xss"
    description = "Detect reflected XSS in URL query parameters and HTML forms"
    version = "1.0.0"

    def __init__(self, config: FrameworkConfig) -> None:
        super().__init__(config)
        self._payload_engine = PayloadEngine(config.payloads)

    async def run(
        self,
        target: str,
        *,
        scan_forms: bool = False,
        crawl: bool = False,
        custom_payloads: Optional[list[str]] = None,
        payload_file: Optional[str] = None,
        browser_confirm: bool = False,
        **kwargs: Any,
    ) -> ModuleResult:
        """
        Scan *target* for reflected XSS vulnerabilities.

        Args:
            target: Seed URL.  Include query parameters for direct parameter
                    testing; omit them when relying on ``crawl=True``.
            scan_forms: Discover and test HTML forms on the target page(s).
            crawl: Crawl the target site for additional parameterised URLs
                   and forms before scanning.
            custom_payloads: In-memory payload list.  Overrides file-based
                             loading when provided.
            payload_file: Path to a user-supplied TXT or JSON payload file.
                          Ignored when *custom_payloads* is set.
            **kwargs: Absorbed for forward-compatibility with the BaseModule API.

        Returns:
            :class:`~modules.base.ModuleResult` with all confirmed findings.
        """
        target = normalize_url(target)
        self._logger.info("Starting %s scan against: %s", self.name, target)

        payloads = custom_payloads or self._payload_engine.load(
            Path(payload_file) if payload_file else None
        )

        result = ModuleResult(
            module_name=self.name,
            target=target,
            metadata={"payloads_loaded": len(payloads)},
        )

        async with HTTPClient(self._config.scanner) as http:
            scanner = Scanner(self._config, http)
            scan_results: list[ScanResult] = []

            urls_to_scan: list[str] = []
            forms_to_scan: list = []

            if crawl:
                crawler = Crawler(self._config.crawler, http)
                crawl_data = await crawler.crawl(target)
                urls_to_scan = crawl_data.urls_with_params or (
                    [target] if extract_params(target) else []
                )
                forms_to_scan = crawl_data.forms if scan_forms else []
            else:
                if extract_params(target):
                    urls_to_scan = [target]
                elif not scan_forms:
                    self._logger.warning(
                        "No query parameters detected in target URL. "
                        "Use --forms to scan HTML forms or --crawl to discover endpoints."
                    )

                if scan_forms:
                    forms_to_scan = await self._discover_forms(target, http)

            # Scan parameterised URLs
            for url in urls_to_scan:
                sr = await scanner.scan_url(url, payloads)
                scan_results.append(sr)

            # Scan forms
            for form in forms_to_scan:
                sr = await scanner.scan_form(form, payloads)
                scan_results.append(sr)

        # ── Phase 2: context-aware upgrade for LOW SCRIPT_STRING findings ──────
        # For each parameter that got a LOW-confidence SCRIPT_STRING hit,
        # run a targeted second pass with JS string-break payloads to try to
        # escalate confidence before we deduplicate.
        js_payloads = self._payload_engine.load_for_context("script_block")
        if js_payloads:
            upgrade_tasks = []
            for sr in scan_results:
                for finding in sr.findings:
                    if (
                        finding.confidence == ConfidenceLevel.LOW
                        and finding.reflection_context == "SCRIPT_STRING"
                    ):
                        upgrade_tasks.append((sr, finding))

            for sr, low_finding in upgrade_tasks:
                async with HTTPClient(self._config.scanner) as http2:
                    scanner2 = Scanner(self._config, http2)
                    upgraded_sr = await scanner2.scan_url(low_finding.target_url, js_payloads)
                    sr.payloads_tested += upgraded_sr.payloads_tested
                    for upgraded in upgraded_sr.findings:
                        if upgraded.parameter == low_finding.parameter:
                            if upgraded.confidence > low_finding.confidence:
                                sr.findings.remove(low_finding)
                                sr.findings.append(upgraded)
                                self._logger.info(
                                    "Upgraded %r finding %s→%s via JS string-break payloads",
                                    upgraded.parameter,
                                    low_finding.confidence.name,
                                    upgraded.confidence.name,
                                )
                            break

        # ── Aggregate all findings ───────────────────────────────────────────
        total_payloads = 0
        total_params = 0
        raw_findings: list[dict] = []
        for sr in scan_results:
            total_payloads += sr.payloads_tested
            total_params += sr.parameters_tested
            result.errors.extend(sr.errors)
            for finding in sr.findings:
                raw_findings.append({
                    "type":                     finding.finding_type,
                    "severity":                 finding.severity,
                    "severity_score":           _severity_score(finding.confidence, finding.reflection_context),
                    "confidence":               finding.confidence.value,
                    "confidence_label":         finding.confidence.name,
                    "parameter":                finding.parameter,
                    "payload":                  finding.payload,
                    "attack_url":               finding.attack_url,
                    "evidence":                 finding.evidence,
                    "reflection_context":       finding.reflection_context,
                    "exploitation_notes":       finding.exploitation_notes,
                    "encoding_types":           list(finding.encoding_types),
                    "dangerous_chars_preserved": list(finding.dangerous_chars_preserved),
                    "exploitation_difficulty":  finding.exploitation_difficulty,
                })

        # ── Phase 3: CSTI probing ────────────────────────────────────────────
        async with HTTPClient(self._config.scanner) as http_csti:
            csti_scanner = Scanner(self._config, http_csti)
            csti_urls = list(dict.fromkeys(urls_to_scan))  # deduplicated
            for csti_url in csti_urls:
                csti_findings = await csti_scanner.scan_csti(csti_url)
                total_payloads += len(extract_params(csti_url))
                for f in csti_findings:
                    raw_findings.append({
                        "type":                     f.finding_type,
                        "severity":                 f.severity,
                        "severity_score":           _severity_score(f.confidence, f.reflection_context),
                        "confidence":               f.confidence.value,
                        "confidence_label":         f.confidence.name,
                        "parameter":                f.parameter,
                        "payload":                  f.payload,
                        "attack_url":               f.attack_url,
                        "evidence":                 f.evidence,
                        "reflection_context":       f.reflection_context,
                        "exploitation_notes":       f.exploitation_notes,
                        "encoding_types":           list(f.encoding_types),
                        "dangerous_chars_preserved": list(f.dangerous_chars_preserved),
                        "exploitation_difficulty":  f.exploitation_difficulty,
                    })

        # ── Phase 4: Browser confirmation (optional) ─────────────────────────
        if browser_confirm and _BROWSER_AVAILABLE:
            confirmer = BrowserConfirmer()
            if await confirmer.is_available():
                confirmed: list[dict] = []
                for f in raw_findings:
                    if f["type"] == "Template Injection (CSTI)":
                        confirmed.append(f)
                        continue
                    browser_hit = await confirmer.confirm_xss(f["attack_url"])
                    if browser_hit:
                        f = dict(f)
                        f["confidence"] = ConfidenceLevel.CRITICAL.value
                        f["confidence_label"] = "CRITICAL"
                        f["severity"] = "CRITICAL"
                        f["severity_score"] = 10.0
                        f["exploitation_notes"] = (
                            "[BROWSER CONFIRMED] alert() executed in headless browser. "
                            + f.get("exploitation_notes", "")
                        )
                        confirmed.append(f)
                    else:
                        confirmed.append(f)
                raw_findings = confirmed

        # ── Phase 5: Deduplicate ─────────────────────────────────────────────
        # Keep the highest-scoring finding per (parameter, finding_type) pair.
        # This collapses duplicate LOW findings for the same parameter across
        # multiple crawled pages into a single representative finding.
        result.findings = self._deduplicate_findings(raw_findings)

        result.metadata["payloads_tested"] = total_payloads
        result.metadata["parameters_tested"] = total_params

        self._logger.info(
            "Scan complete: %d finding(s) across %d payload(s) tested",
            len(result.findings),
            total_payloads,
        )
        return result

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _discover_forms(self, url: str, http: HTTPClient) -> list:
        """Fetch *url* and parse its forms without a full crawl."""
        response = await http.get(url)
        if response is None:
            self._logger.warning("Could not fetch page for form discovery: %s", url)
            return []

        soup = BeautifulSoup(response.text, "html.parser")
        # Reuse the crawler's form-extraction logic
        crawler = Crawler(self._config.crawler, http)
        forms = crawler._extract_forms(soup, url)
        self._logger.info("Discovered %d form(s) on: %s", len(forms), url)
        return forms

    @staticmethod
    def _deduplicate_findings(findings: list[dict]) -> list[dict]:
        """
        Return one finding per (parameter, finding_type) pair — the highest-scoring one.

        Prevents report clutter when the same vulnerable parameter is discovered
        across multiple crawled URLs with the same injection type.
        """
        best: dict[tuple[str, str], dict] = {}
        for f in findings:
            key = (f.get("parameter", ""), f.get("type", ""))
            existing = best.get(key)
            if existing is None or f.get("severity_score", 0) > existing.get("severity_score", 0):
                best[key] = f
        return list(best.values())
