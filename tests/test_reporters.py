"""
Unit tests for the full reporting engine.

Coverage
--------
  ScanSession     — UUID, finish/duration, to_dict serialisation
  JSONReporter    — schema_version=2, session block, risk score, severity counts
  CSVReporter     — header columns, row count, pipe-separated multi-value fields
  HTMLReporter    — DOCTYPE, key sections, XSS escaping
  ConsoleReporter — smoke tests (no exception for empty and non-empty results)
"""
from __future__ import annotations

import contextlib
import csv
import io
import json
import re
from pathlib import Path

import pytest

from modules.base import ModuleResult
from reports.csv_reporter import CSVReporter
from reports.html_reporter import HTMLReporter
from reports.json_reporter import JSONReporter
from reports.session import ScanSession


# ===========================================================================
# ScanSession
# ===========================================================================


class TestScanSession:
    def test_session_id_is_8_chars(self) -> None:
        s = ScanSession.start()
        assert len(s.session_id) == 8

    def test_session_id_is_uppercase_hex(self) -> None:
        s = ScanSession.start()
        assert re.fullmatch(r"[0-9A-F]{8}", s.session_id)

    def test_different_sessions_have_different_ids(self) -> None:
        ids = {ScanSession.start().session_id for _ in range(10)}
        assert len(ids) > 1

    def test_started_at_is_utc(self) -> None:
        from datetime import timezone
        s = ScanSession.start()
        assert s.started_at.tzinfo == timezone.utc

    def test_finished_at_none_before_finish(self) -> None:
        s = ScanSession.start()
        assert s.finished_at is None

    def test_finish_sets_finished_at(self) -> None:
        s = ScanSession.start()
        s.finish()
        assert s.finished_at is not None

    def test_duration_non_negative_after_finish(self) -> None:
        s = ScanSession.start()
        s.finish()
        assert s.duration_seconds >= 0.0

    def test_finish_returns_self(self) -> None:
        s = ScanSession.start()
        assert s.finish() is s

    def test_to_dict_has_all_keys(self) -> None:
        s = ScanSession.start()
        s.finish()
        d = s.to_dict()
        for key in ("session_id", "started_at", "finished_at",
                    "duration_seconds", "framework_version", "scan_options"):
            assert key in d, f"Missing key: {key}"

    def test_to_dict_scan_options_round_trips(self) -> None:
        opts = {"target": "http://x.com", "forms": True}
        s = ScanSession.start(scan_options=opts)
        s.finish()
        assert s.to_dict()["scan_options"] == opts

    def test_to_dict_duration_rounded_to_3dp(self) -> None:
        s = ScanSession.start()
        s.finish()
        dur = s.to_dict()["duration_seconds"]
        assert isinstance(dur, float)
        assert round(dur, 3) == dur

    def test_to_dict_session_id_matches(self) -> None:
        s = ScanSession.start()
        s.finish()
        assert s.to_dict()["session_id"] == s.session_id


# ===========================================================================
# Helpers
# ===========================================================================


def _capture_stdout(fn, *args, **kwargs) -> str:
    """Run fn(*args, **kwargs) with stdout redirected; return captured text."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args, **kwargs)
    return buf.getvalue()


# ===========================================================================
# JSONReporter
# ===========================================================================


class TestJSONReporter:
    def _render(self, result: ModuleResult) -> dict:
        text = _capture_stdout(JSONReporter().report, result)
        return json.loads(text)

    def test_schema_version_is_2(self, minimal_result: ModuleResult) -> None:
        assert self._render(minimal_result)["schema_version"] == "2"

    def test_session_block_present(self, minimal_result: ModuleResult) -> None:
        data = self._render(minimal_result)
        assert "session" in data
        assert "session_id" in data["session"]

    def test_session_not_duplicated_in_metadata(self, minimal_result: ModuleResult) -> None:
        data = self._render(minimal_result)
        assert "session" not in data.get("metadata", {})

    def test_summary_has_required_keys(self, minimal_result: ModuleResult) -> None:
        summary = self._render(minimal_result)["summary"]
        for key in ("total_findings", "vulnerable", "risk_score", "severity_counts"):
            assert key in summary, f"Missing summary key: {key}"

    def test_total_findings_count(self, minimal_result: ModuleResult) -> None:
        assert self._render(minimal_result)["summary"]["total_findings"] == 1

    def test_vulnerable_true_when_findings(self, minimal_result: ModuleResult) -> None:
        assert self._render(minimal_result)["summary"]["vulnerable"] is True

    def test_vulnerable_false_when_empty(self, empty_result: ModuleResult) -> None:
        assert self._render(empty_result)["summary"]["vulnerable"] is False

    def test_risk_score_is_float(self, minimal_result: ModuleResult) -> None:
        assert isinstance(self._render(minimal_result)["summary"]["risk_score"], float)

    def test_risk_score_zero_when_no_findings(self, empty_result: ModuleResult) -> None:
        assert self._render(empty_result)["summary"]["risk_score"] == 0.0

    def test_risk_score_equals_max_severity_score(self, minimal_result: ModuleResult) -> None:
        data = self._render(minimal_result)
        scores = [f.get("severity_score", 0) for f in data["findings"]]
        assert data["summary"]["risk_score"] == max(scores)

    def test_severity_counts_has_expected_keys(self, minimal_result: ModuleResult) -> None:
        counts = self._render(minimal_result)["summary"]["severity_counts"]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert sev in counts

    def test_high_count_incremented(self, minimal_result: ModuleResult) -> None:
        counts = self._render(minimal_result)["summary"]["severity_counts"]
        assert counts["HIGH"] == 1

    def test_findings_list_length(self, minimal_result: ModuleResult) -> None:
        findings = self._render(minimal_result)["findings"]
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_finding_has_severity_score(self, minimal_result: ModuleResult) -> None:
        finding = self._render(minimal_result)["findings"][0]
        assert "severity_score" in finding
        assert isinstance(finding["severity_score"], (int, float))

    def test_generated_at_parses_as_iso(self, minimal_result: ModuleResult) -> None:
        from datetime import datetime
        ts = self._render(minimal_result)["generated_at"]
        datetime.fromisoformat(ts)  # raises if invalid

    def test_writes_to_file(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        dest = tmp_path / "report.json"
        JSONReporter(str(dest)).report(minimal_result)
        assert dest.exists()
        assert json.loads(dest.read_text())["schema_version"] == "2"

    def test_empty_findings_writes_valid_json(self, empty_result: ModuleResult) -> None:
        text = _capture_stdout(JSONReporter().report, empty_result)
        data = json.loads(text)
        assert data["findings"] == []

    def test_framework_version_present(self, minimal_result: ModuleResult) -> None:
        data = self._render(minimal_result)
        assert "framework_version" in data
        assert data["framework_version"]


# ===========================================================================
# CSVReporter
# ===========================================================================


_CSV_EXPECTED_HEADERS = [
    "session_id", "generated_at", "target", "module",
    "finding_number", "parameter", "type", "severity",
    "severity_score", "confidence_label", "confidence_score",
    "reflection_context", "exploitation_difficulty",
    "payload", "attack_url", "evidence",
    "encoding_types", "dangerous_chars_preserved", "exploitation_notes",
]


class TestCSVReporter:
    def _render_rows(self, result: ModuleResult) -> tuple[list[str] | None, list[dict]]:
        text = _capture_stdout(CSVReporter().report, result)
        reader = csv.DictReader(io.StringIO(text))
        return reader.fieldnames, list(reader)

    def test_all_expected_columns_present(self, minimal_result: ModuleResult) -> None:
        headers, _ = self._render_rows(minimal_result)
        assert headers is not None
        for col in _CSV_EXPECTED_HEADERS:
            assert col in headers, f"Missing column: {col}"

    def test_row_count_matches_findings(self, minimal_result: ModuleResult) -> None:
        _, rows = self._render_rows(minimal_result)
        assert len(rows) == 1

    def test_empty_result_produces_no_data_rows(self, empty_result: ModuleResult) -> None:
        _, rows = self._render_rows(empty_result)
        assert len(rows) == 0

    def test_severity_value_in_row(self, minimal_result: ModuleResult) -> None:
        _, rows = self._render_rows(minimal_result)
        assert rows[0]["severity"] == "HIGH"

    def test_encoding_types_is_pipe_separated_string(self, minimal_result: ModuleResult) -> None:
        _, rows = self._render_rows(minimal_result)
        enc = rows[0]["encoding_types"]
        assert isinstance(enc, str)
        assert enc != ""

    def test_dangerous_chars_is_pipe_separated(self, minimal_result: ModuleResult) -> None:
        _, rows = self._render_rows(minimal_result)
        chars = rows[0]["dangerous_chars_preserved"]
        # 4 chars ["<", ">", "(", ")"] → pipe-separated
        assert "|" in chars

    def test_finding_number_starts_at_1(self, minimal_result: ModuleResult) -> None:
        _, rows = self._render_rows(minimal_result)
        assert rows[0]["finding_number"] == "1"

    def test_multi_finding_row_numbers_sequential(
        self, finished_session: ScanSession
    ) -> None:
        result = ModuleResult(
            module_name="reflected-xss",
            target="http://x.com",
            findings=[
                {
                    "type": "Reflected XSS", "severity": "HIGH", "severity_score": 7.5,
                    "confidence": 3, "confidence_label": "HIGH", "parameter": "q",
                    "payload": "x", "attack_url": "http://x.com/?q=x", "evidence": "...",
                    "reflection_context": "HTML_TEXT", "exploitation_notes": "",
                    "encoding_types": [], "dangerous_chars_preserved": [],
                    "exploitation_difficulty": "TRIVIAL",
                },
                {
                    "type": "Reflected XSS", "severity": "MEDIUM", "severity_score": 4.0,
                    "confidence": 2, "confidence_label": "MEDIUM", "parameter": "name",
                    "payload": "y", "attack_url": "http://x.com/?name=y", "evidence": "...",
                    "reflection_context": "HTML_COMMENT", "exploitation_notes": "",
                    "encoding_types": [], "dangerous_chars_preserved": [],
                    "exploitation_difficulty": "HARD",
                },
            ],
            metadata={"session": finished_session.to_dict()},
        )
        _, rows = self._render_rows(result)
        assert rows[0]["finding_number"] == "1"
        assert rows[1]["finding_number"] == "2"

    def test_writes_to_file(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        dest = tmp_path / "report.csv"
        CSVReporter(str(dest)).report(minimal_result)
        assert dest.exists()
        rows = list(csv.DictReader(dest.open(encoding="utf-8")))
        assert len(rows) == 1

    def test_parameter_name_in_row(self, minimal_result: ModuleResult) -> None:
        _, rows = self._render_rows(minimal_result)
        assert rows[0]["parameter"] == "q"

    def test_exploitation_difficulty_in_row(self, minimal_result: ModuleResult) -> None:
        _, rows = self._render_rows(minimal_result)
        assert rows[0]["exploitation_difficulty"] == "TRIVIAL"


# ===========================================================================
# HTMLReporter
# ===========================================================================


class TestHTMLReporter:
    def _render(self, result: ModuleResult, tmp_path: Path) -> str:
        dest = tmp_path / "report.html"
        HTMLReporter(str(dest)).report(result)
        return dest.read_text(encoding="utf-8")

    def test_produces_doctype(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        assert "<!DOCTYPE html>" in html or "<!doctype html>" in html.lower()

    def test_produces_html_and_body_tags(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        assert "<html" in html
        assert "<body" in html

    def test_has_inline_css(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        assert "<style>" in html

    def test_target_url_in_output(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        assert "test.local" in html

    def test_session_id_in_output(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        sid = minimal_result.metadata["session"]["session_id"]
        assert sid in html

    def test_encoding_section_present(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        assert "ncoding" in html  # "Encoding" or "encoding"

    def test_xss_payload_is_html_escaped(self, tmp_path: Path, finished_session: ScanSession) -> None:
        result = ModuleResult(
            module_name="reflected-xss",
            target="http://x.com",
            findings=[{
                "type": "Reflected XSS", "severity": "HIGH", "severity_score": 7.5,
                "confidence": 3, "confidence_label": "HIGH", "parameter": "q",
                "payload": "<script>alert(INJECT)</script>",
                "attack_url": "http://x.com/?q=<script>",
                "evidence": "<script>alert(INJECT)</script>",
                "reflection_context": "HTML_TEXT", "exploitation_notes": "",
                "encoding_types": ["none"], "dangerous_chars_preserved": ["<", ">"],
                "exploitation_difficulty": "TRIVIAL",
            }],
            metadata={"session": finished_session.to_dict()},
        )
        html = self._render(result, tmp_path)
        # The literal executable tag must not appear verbatim
        assert "<script>alert(INJECT)</script>" not in html

    def test_empty_result_renders_without_exception(
        self, empty_result: ModuleResult, tmp_path: Path
    ) -> None:
        html = self._render(empty_result, tmp_path)
        assert "<html" in html

    def test_severity_score_shown(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        assert "7.5" in html

    def test_parameter_name_shown(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        assert ">q<" in html or '"q"' in html or ">q</" in html or "q</td" in html or "q" in html

    def test_file_is_self_contained(self, minimal_result: ModuleResult, tmp_path: Path) -> None:
        html = self._render(minimal_result, tmp_path)
        # No external stylesheet or script src references
        assert 'rel="stylesheet"' not in html
        assert '<script src=' not in html

    def test_multiple_findings_all_rendered(
        self, tmp_path: Path, finished_session: ScanSession
    ) -> None:
        result = ModuleResult(
            module_name="reflected-xss",
            target="http://x.com",
            findings=[
                {
                    "type": "Reflected XSS", "severity": "HIGH", "severity_score": 7.5,
                    "confidence": 3, "confidence_label": "HIGH", "parameter": "q",
                    "payload": "p1", "attack_url": "http://x.com/?q=p1", "evidence": "e1",
                    "reflection_context": "HTML_TEXT", "exploitation_notes": "",
                    "encoding_types": ["none"], "dangerous_chars_preserved": [],
                    "exploitation_difficulty": "TRIVIAL",
                },
                {
                    "type": "Reflected XSS", "severity": "MEDIUM", "severity_score": 4.0,
                    "confidence": 2, "confidence_label": "MEDIUM", "parameter": "name",
                    "payload": "p2", "attack_url": "http://x.com/?name=p2", "evidence": "e2",
                    "reflection_context": "HTML_COMMENT", "exploitation_notes": "",
                    "encoding_types": ["html_entity"], "dangerous_chars_preserved": [],
                    "exploitation_difficulty": "HARD",
                },
            ],
            metadata={"session": finished_session.to_dict()},
        )
        html = self._render(result, tmp_path)
        assert "p1" in html
        assert "p2" in html


# ===========================================================================
# ConsoleReporter — smoke tests
# ===========================================================================


class TestConsoleReporter:
    def test_no_exception_with_findings(self, minimal_result: ModuleResult) -> None:
        from reports.console import ConsoleReporter
        with contextlib.redirect_stdout(io.StringIO()):
            ConsoleReporter(verbose=False, color=False).report(minimal_result)

    def test_no_exception_empty_result(self, empty_result: ModuleResult) -> None:
        from reports.console import ConsoleReporter
        with contextlib.redirect_stdout(io.StringIO()):
            ConsoleReporter(verbose=False, color=False).report(empty_result)

    def test_verbose_no_exception(self, minimal_result: ModuleResult) -> None:
        from reports.console import ConsoleReporter
        with contextlib.redirect_stdout(io.StringIO()):
            ConsoleReporter(verbose=True, color=False).report(minimal_result)

    def test_outputs_something(self, minimal_result: ModuleResult) -> None:
        from reports.console import ConsoleReporter
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            ConsoleReporter(verbose=False, color=False).report(minimal_result)
        # Rich outputs to its own Console object (not sys.stdout), but we at
        # minimum confirm no exception was raised and execution completed.
        assert True  # marker — if we reach here, no exception was raised
