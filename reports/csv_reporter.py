"""CSV reporter — exports findings as a flat, machine-readable CSV file."""
from __future__ import annotations

import csv
import io
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from modules.base import ModuleResult
from reports.base import BaseReporter

_FIELDNAMES = [
    "session_id",
    "generated_at",
    "target",
    "module",
    "finding_number",
    "parameter",
    "type",
    "severity",
    "severity_score",
    "confidence_label",
    "confidence_score",
    "reflection_context",
    "exploitation_difficulty",
    "payload",
    "attack_url",
    "evidence",
    "encoding_types",
    "dangerous_chars_preserved",
    "exploitation_notes",
]


class CSVReporter(BaseReporter):
    """
    Exports scan findings to a flat CSV file.

    Each row is one finding.  Multi-value fields (``encoding_types``,
    ``dangerous_chars_preserved``) are pipe-separated.

    Args:
        output_file: Path to write the CSV.  ``None`` writes to stdout.
    """

    def __init__(self, output_file: Optional[str] = None) -> None:
        self._output_file = Path(output_file) if output_file else None

    def report(self, result: ModuleResult) -> None:
        """Write *result* findings to CSV."""
        generated = datetime.now(timezone.utc).isoformat()
        session   = result.metadata.get("session", {})
        session_id = session.get("session_id", "")

        rows = [
            self._finding_row(f, idx, session_id, generated, result)
            for idx, f in enumerate(result.findings, start=1)
        ]

        if self._output_file:
            self._output_file.parent.mkdir(parents=True, exist_ok=True)
            with self._output_file.open("w", newline="", encoding="utf-8") as fh:
                self._write(fh, rows)
            print(f"[+] CSV report written to: {self._output_file}", file=sys.stderr)
        else:
            buf = io.StringIO()
            self._write(buf, rows)
            sys.stdout.write(buf.getvalue())

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _write(fh: io.IOBase, rows: list[dict]) -> None:
        writer = csv.DictWriter(fh, fieldnames=_FIELDNAMES, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    @staticmethod
    def _finding_row(
        f: dict,
        idx: int,
        session_id: str,
        generated: str,
        result: ModuleResult,
    ) -> dict:
        enc   = f.get("encoding_types", [])
        chars = f.get("dangerous_chars_preserved", [])
        return {
            "session_id":              session_id,
            "generated_at":            generated,
            "target":                  result.target,
            "module":                  result.module_name,
            "finding_number":          idx,
            "parameter":               f.get("parameter", ""),
            "type":                    f.get("type", "Reflected XSS"),
            "severity":                f.get("severity", ""),
            "severity_score":          f.get("severity_score", ""),
            "confidence_label":        f.get("confidence_label", f.get("severity", "")),
            "confidence_score":        f.get("confidence", ""),
            "reflection_context":      f.get("reflection_context", ""),
            "exploitation_difficulty": f.get("exploitation_difficulty", ""),
            "payload":                 f.get("payload", ""),
            "attack_url":              f.get("attack_url", ""),
            "evidence":                (f.get("evidence") or "").replace("\n", " "),
            "encoding_types":          "|".join(enc) if isinstance(enc, list) else str(enc),
            "dangerous_chars_preserved": "|".join(chars) if isinstance(chars, list) else str(chars),
            "exploitation_notes":      f.get("exploitation_notes", ""),
        }
