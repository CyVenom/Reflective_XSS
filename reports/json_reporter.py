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


class JSONReporter(BaseReporter):
    """
    Serialises a :class:`~modules.base.ModuleResult` to JSON.

    Output schema:

    .. code-block:: json

        {
          "generated_at": "2025-01-01T00:00:00Z",
          "framework_version": "1.0.0",
          "module": "reflected-xss",
          "target": "https://example.com/search?q=test",
          "metadata": { "payloads_loaded": 150, ... },
          "summary": { "total_findings": 2, "vulnerable": true },
          "findings": [ { "type": "...", "severity": "HIGH", ... } ],
          "errors": []
        }

    Args:
        output_file: Path to write the JSON report.  ``None`` writes to stdout.
    """

    _FRAMEWORK_VERSION = "1.0.0"

    def __init__(self, output_file: Optional[str] = None) -> None:
        self._output_file = Path(output_file) if output_file else None

    def report(self, result: ModuleResult) -> None:
        """Serialise *result* to JSON and write to the configured destination."""
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "framework_version": self._FRAMEWORK_VERSION,
            "module": result.module_name,
            "target": result.target,
            "metadata": result.metadata,
            "summary": {
                "total_findings": len(result.findings),
                "vulnerable": result.vulnerable,
            },
            "findings": result.findings,
            "errors": result.errors,
        }

        text = json.dumps(payload, indent=2, ensure_ascii=False)

        if self._output_file:
            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            self._output_file.write_text(text, encoding="utf-8")
            print(
                f"[+] JSON report written to: {self._output_file}",
                file=sys.stderr,
            )
        else:
            print(text)
