"""
JSON reporter — serialises scan results to structured JSON.

Writes to a file when ``output_file`` is provided, or to ``stdout`` otherwise.
The JSON schema is designed for machine consumption: downstream SIEM tools,
issue trackers, or CI/CD pipelines can parse it without understanding the
framework's Python types.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from modules.base import ModuleResult
from reports.base import BaseReporter

_FRAMEWORK_VERSION = "1.0.0"


class JSONReporter(BaseReporter):
    """
    Serialises a :class:`~modules.base.ModuleResult` to JSON.

    Output schema (abbreviated)::

        {
          "schema_version": "2",
          "generated_at": "2025-01-01T00:00:00+00:00",
          "framework_version": "1.0.0",
          "session": { "session_id": "A1B2C3D4", "started_at": "...", ... },
          "module": "reflected-xss",
          "target": "https://example.com/search?q=test",
          "metadata": { "payloads_loaded": 150, ... },
          "summary": {
            "total_findings": 2,
            "vulnerable": true,
            "risk_score": 8.5,
            "severity_counts": { "CRITICAL": 0, "HIGH": 2, "MEDIUM": 0, "LOW": 0 }
          },
          "findings": [
            {
              "type": "Reflected XSS",
              "severity": "HIGH",
              "severity_score": 7.5,
              "confidence": 3,
              "confidence_label": "HIGH",
              "parameter": "q",
              "payload": "...",
              "attack_url": "...",
              "evidence": "...",
              "reflection_context": "HTML_TEXT",
              "exploitation_notes": "...",
              "encoding_types": ["none"],
              "dangerous_chars_preserved": ["<", ">"],
              "exploitation_difficulty": "TRIVIAL"
            }
          ],
          "errors": []
        }

    Args:
        output_file: Path to write the JSON report.  ``None`` writes to stdout.
    """

    def __init__(self, output_file: Optional[str] = None) -> None:
        self._output_file = Path(output_file) if output_file else None

    def report(self, result: ModuleResult) -> None:
        """Serialise *result* to JSON and write to the configured destination."""
        payload = self._build(result)
        text    = json.dumps(payload, indent=2, ensure_ascii=False)

        if self._output_file:
            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            self._output_file.write_text(text, encoding="utf-8")
            print(f"[+] JSON report written to: {self._output_file}", file=sys.stderr)
        else:
            print(text)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _build(result: ModuleResult) -> dict:
        findings = result.findings
        session  = result.metadata.get("session", {})

        # Severity breakdown
        sev_counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        scores: list[float] = []
        for f in findings:
            sev = (f.get("severity") or "HIGH").upper()
            if sev in sev_counts:
                sev_counts[sev] += 1
            score = f.get("severity_score")
            if isinstance(score, (int, float)):
                scores.append(float(score))

        risk_score = round(max(scores), 1) if scores else 0.0

        return {
            "schema_version":   "2",
            "generated_at":     datetime.now(timezone.utc).isoformat(),
            "framework_version": _FRAMEWORK_VERSION,
            "session":          session,
            "module":           result.module_name,
            "target":           result.target,
            "metadata":         {
                k: v for k, v in result.metadata.items() if k != "session"
            },
            "summary": {
                "total_findings":  len(findings),
                "vulnerable":      result.vulnerable,
                "risk_score":      risk_score,
                "severity_counts": sev_counts,
            },
            "findings": findings,
            "errors":   result.errors,
        }
