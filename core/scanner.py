"""
Core async scanning engine.

Orchestrates payload injection into URL query parameters and HTML form fields,
then delegates reflection analysis to :mod:`core.reflection`.  Concurrency is
bounded by an ``asyncio.Semaphore`` derived from :attr:`ScannerConfig.concurrency`.

Design decisions:
- One :class:`Finding` is emitted per vulnerable (parameter, payload) pair.
- Scanning stops at the first confirmed hit *per parameter* to avoid flooding
  the target with redundant requests once vulnerability is established.
- All I/O is async; CPU-bound reflection checks run inline (they are fast).
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Optional

from core.config import FrameworkConfig
from core.crawler import Form
from core.reflection import ConfidenceLevel, ReflectionAnalyzer, ReflectionContext
from utils.helpers import (
    build_url_with_param,
    extract_params,
    generate_marker,
    inject_marker_into_payload,
)
from utils.http import HTTPClient

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Result models
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A confirmed reflected-XSS vulnerability."""

    target_url: str
    """The original un-modified URL."""

    parameter: str
    """The query parameter or form field name that is injectable."""

    payload: str
    """The exact payload (with embedded marker) that triggered reflection."""

    attack_url: str
    """The full URL or form action that demonstrated the reflection."""

    evidence: str
    """A short excerpt of the response body showing the reflected marker."""

    severity: str = "HIGH"
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    finding_type: str = "Reflected XSS"
    reflection_context: str = ReflectionContext.UNKNOWN.name
    exploitation_notes: str = ""
    encoding_types: tuple[str, ...] = ()
    dangerous_chars_preserved: tuple[str, ...] = ()
    exploitation_difficulty: str = "UNKNOWN"


@dataclass
class ScanResult:
    """Aggregate result of scanning one URL or form."""

    target_url: str
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    payloads_tested: int = 0
    parameters_tested: int = 0
    elapsed: float = 0.0

    @property
    def vulnerable(self) -> bool:
        return bool(self.findings)


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------


class Scanner:
    """
    Async scanner that tests URL parameters and HTML form fields for rXSS.

    Usage::

        async with HTTPClient(config.scanner) as http:
            scanner = Scanner(config, http)
            result = await scanner.scan_url(url, payloads)
    """

    def __init__(self, config: FrameworkConfig, http_client: HTTPClient) -> None:
        self._config = config
        self._http = http_client
        self._reflection = ReflectionAnalyzer()
        self._semaphore = asyncio.Semaphore(config.scanner.concurrency)

    # ------------------------------------------------------------------
    # Public scanning API
    # ------------------------------------------------------------------

    async def scan_url(self, url: str, payloads: list[str]) -> ScanResult:
        """
        Test all query parameters in *url* against every payload in *payloads*.

        Args:
            url: Target URL.  Must contain at least one query parameter.
            payloads: XSS payload strings to inject.

        Returns:
            A :class:`ScanResult` with zero or more :class:`Finding` objects.
        """
        start = time.monotonic()
        result = ScanResult(target_url=url)
        params = extract_params(url)

        if not params:
            logger.warning("No query parameters found in: %s", url)
            return result

        logger.info("Testing %d parameter(s) in %s", len(params), url)

        tasks = [
            self._scan_url_parameter(url, params, param, payloads, result)
            for param in params
        ]
        await asyncio.gather(*tasks)

        result.parameters_tested = len(params)
        result.elapsed = time.monotonic() - start
        return result

    async def scan_form(self, form: Form, payloads: list[str]) -> ScanResult:
        """
        Test all injectable fields in *form* against every payload in *payloads*.

        Args:
            form: Parsed HTML form with action URL, method, and fields.
            payloads: XSS payload strings to inject.

        Returns:
            A :class:`ScanResult` with zero or more :class:`Finding` objects.
        """
        start = time.monotonic()
        result = ScanResult(target_url=form.action)
        injectable = form.injectable_fields()

        if not injectable:
            logger.debug("No injectable fields in form at: %s", form.action)
            return result

        tasks = [
            self._scan_form_field(form, fld.name, payloads, result)
            for fld in injectable
        ]
        await asyncio.gather(*tasks)

        result.parameters_tested = len(injectable)
        result.elapsed = time.monotonic() - start
        return result

    # ------------------------------------------------------------------
    # Per-parameter / per-field orchestration
    # ------------------------------------------------------------------

    async def _scan_url_parameter(
        self,
        url: str,
        params: dict[str, str],
        param: str,
        payloads: list[str],
        result: ScanResult,
    ) -> None:
        for payload in payloads:
            finding = await self._probe_url_param(url, params, param, payload, result)
            if finding:
                result.findings.append(finding)
                logger.info(
                    "[VULN] param=%r context=%s url=%s",
                    param,
                    finding.reflection_context,
                    finding.attack_url,
                )
                return  # one confirmed hit per parameter is enough

    async def _scan_form_field(
        self,
        form: Form,
        field_name: str,
        payloads: list[str],
        result: ScanResult,
    ) -> None:
        for payload in payloads:
            finding = await self._probe_form_field(form, field_name, payload, result)
            if finding:
                result.findings.append(finding)
                logger.info(
                    "[VULN] form-field=%r action=%s",
                    field_name,
                    form.action,
                )
                return

    # ------------------------------------------------------------------
    # Single-probe helpers
    # ------------------------------------------------------------------

    async def _probe_url_param(
        self,
        url: str,
        params: dict[str, str],
        param: str,
        payload: str,
        result: ScanResult,
    ) -> Optional[Finding]:
        """Inject *payload* into *param* and check the response for reflection."""
        marker = generate_marker()
        marked_payload = inject_marker_into_payload(payload, marker)
        attack_url = build_url_with_param(url, params, param, marked_payload)

        async with self._semaphore:
            response = await self._http.get(attack_url)
            result.payloads_tested += 1

        if response is None:
            result.errors.append(f"No response for: {attack_url}")
            return None

        reflection = self._reflection.analyze(response.text, marker, payload=marked_payload)
        if not reflection:
            return None

        best = reflection.occurrences[0] if reflection.occurrences else None
        enc  = best.encoding if best else None
        return Finding(
            target_url=url,
            parameter=param,
            payload=marked_payload,
            attack_url=attack_url,
            evidence=reflection.snippet or "",
            severity=reflection.confidence.name,
            confidence=reflection.confidence,
            reflection_context=reflection.context.name,
            exploitation_notes=best.exploitation_notes if best else "",
            encoding_types=enc.encoding_types if enc else (),
            dangerous_chars_preserved=enc.dangerous_chars_preserved if enc else (),
            exploitation_difficulty=enc.exploitation_difficulty if enc else "UNKNOWN",
        )

    async def _probe_form_field(
        self,
        form: Form,
        field_name: str,
        payload: str,
        result: ScanResult,
    ) -> Optional[Finding]:
        """Submit *form* with *payload* in *field_name* and analyse the response."""
        marker = generate_marker()
        marked_payload = inject_marker_into_payload(payload, marker)

        # Build form data: inject into the target field, use defaults for others
        data: dict[str, str] = {
            fld.name: (marked_payload if fld.name == field_name else fld.value)
            for fld in form.fields
        }

        async with self._semaphore:
            if form.method == "POST":
                response = await self._http.post(form.action, data=data)
            else:
                response = await self._http.get(form.action, params=data)
            result.payloads_tested += 1

        if response is None:
            result.errors.append(f"No response for form at: {form.action}")
            return None

        reflection = self._reflection.analyze(response.text, marker, payload=marked_payload)
        if not reflection:
            return None

        best = reflection.occurrences[0] if reflection.occurrences else None
        enc  = best.encoding if best else None
        return Finding(
            target_url=form.action,
            parameter=field_name,
            payload=marked_payload,
            attack_url=response.url,
            evidence=reflection.snippet or "",
            severity=reflection.confidence.name,
            confidence=reflection.confidence,
            reflection_context=reflection.context.name,
            exploitation_notes=best.exploitation_notes if best else "",
            encoding_types=enc.encoding_types if enc else (),
            dangerous_chars_preserved=enc.dangerous_chars_preserved if enc else (),
            exploitation_difficulty=enc.exploitation_difficulty if enc else "UNKNOWN",
        )
