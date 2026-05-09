"""
Performance benchmarks for the XSS framework.

Run
---
    # Basic run
    pytest tests/benchmarks/ -v

    # Save a named baseline
    pytest tests/benchmarks/ --benchmark-save=baseline_v1

    # Compare against saved baseline (shows regressions/improvements)
    pytest tests/benchmarks/ --benchmark-compare=baseline_v1

    # Fail if any benchmark regresses more than 15% vs baseline
    pytest tests/benchmarks/ --benchmark-compare=baseline_v1 --benchmark-compare-fail=mean:15%

    # Generate an HTML histogram
    pytest tests/benchmarks/ --benchmark-histogram

Metrics
-------
  payload_loading       — time to load all default payloads from YAML files
  reflection_analysis   — analysis calls per second across all HTML contexts
  scan_speed            — end-to-end async scan iterations per second
  payload_throughput    — payloads processed per second (no early-stop mock)

Comparison support
------------------
  pytest-benchmark's --benchmark-save / --benchmark-compare handles baseline
  comparison automatically.  BenchmarkSummary (bottom of this file) is a
  standalone, framework-specific utility for saving and comparing runs as JSON
  when pytest-benchmark is not available or for programmatic use.
"""
from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs, urlparse

import pytest

from core.config import FrameworkConfig, PayloadConfig
from core.reflection import ReflectionAnalyzer
from core.scanner import Scanner
from payloads.engine import PayloadEngine
from utils.http import HTTPClient, HTTPResponse


# ---------------------------------------------------------------------------
# Shared test fixtures
# ---------------------------------------------------------------------------

_MARKER = "AbCdEfGh"

_HTML_CONTEXTS: list[tuple[str, str]] = [
    (f"<html><body><p>Hello {_MARKER} world</p></body></html>",                     "html_text"),
    (f'<html><body><input value="{_MARKER}"></body></html>',                         "html_attr"),
    (f"<html><body><script>var q = '{_MARKER}';</script></body></html>",             "script_string"),
    (f"<html><body><script>var q = {_MARKER};</script></body></html>",               "script_block"),
    (f"<html><body><!-- {_MARKER} --></body></html>",                                "html_comment"),
    (f"<html><body><style>/* {_MARKER} */</style></body></html>",                    "style_block"),
    (f'<html><body><img src=x onerror="alert({_MARKER})"></body></html>',            "event_handler"),
    (f'<html><body><a href="https://x.com/?q={_MARKER}">link</a></body></html>',    "attr_url"),
]


def _reflective_http() -> HTTPClient:
    """Mock HTTPClient that echoes the marker into a script context response."""

    async def _get(url: str, **_kw: Any) -> HTTPResponse:
        qs     = parse_qs(urlparse(url).query)
        value  = next(iter(qs.values()), [""])[0]
        match  = re.search(r"[A-Za-z]{8}", value)
        marker = match.group(0) if match else ""
        return HTTPResponse(
            status=200,
            text=f"<html><body><script>var q='{marker}';</script></body></html>",
            headers={},
            url=url,
        )

    http = MagicMock(spec=HTTPClient)
    http.get = AsyncMock(side_effect=_get)
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__  = AsyncMock(return_value=False)
    return http


def _non_reflective_http() -> HTTPClient:
    """Mock HTTPClient that always returns a safe static response."""

    async def _get(url: str, **_kw: Any) -> HTTPResponse:
        return HTTPResponse(
            status=200,
            text="<html><body><p>Safe static page.</p></body></html>",
            headers={},
            url=url,
        )

    http = MagicMock(spec=HTTPClient)
    http.get = AsyncMock(side_effect=_get)
    http.__aenter__ = AsyncMock(return_value=http)
    http.__aexit__  = AsyncMock(return_value=False)
    return http


def _test_config() -> FrameworkConfig:
    cfg = FrameworkConfig.default()
    cfg.scanner.concurrency = 10
    cfg.scanner.timeout     = 5.0
    cfg.scanner.max_retries = 0
    return cfg


# ---------------------------------------------------------------------------
# Payload loading benchmarks
# ---------------------------------------------------------------------------


def test_bench_payload_loading_default(benchmark) -> None:
    """Time to load all default payload files from disk (no mutations)."""
    cfg    = PayloadConfig(use_mutations=False)
    engine = PayloadEngine(cfg)

    result = benchmark(engine.load)
    assert len(result) > 0


def test_bench_payload_loading_with_mutations(benchmark) -> None:
    """Time to load payloads with encoding mutations enabled."""
    cfg    = PayloadConfig(use_mutations=False, use_encoding_mutations=True)
    engine = PayloadEngine(cfg)

    result = benchmark(engine.load)
    assert len(result) > 0


def test_bench_payload_load_entries(benchmark) -> None:
    """Time to load rich PayloadEntry objects via load_entries()."""
    cfg    = PayloadConfig(use_mutations=False)
    engine = PayloadEngine(cfg)

    result = benchmark(engine.load_entries)
    assert len(result) > 0


def test_bench_payload_load_with_waf_bypass(benchmark) -> None:
    """Time to load payloads including the WAF bypass category."""
    cfg    = PayloadConfig(use_mutations=False, use_waf_bypass=True)
    engine = PayloadEngine(cfg)

    result = benchmark(engine.load)
    assert len(result) > 0


# ---------------------------------------------------------------------------
# Reflection analysis benchmarks
# ---------------------------------------------------------------------------


def test_bench_reflection_html_text(benchmark) -> None:
    """Reflection analysis on an HTML text context (most common case)."""
    analyzer = ReflectionAnalyzer()
    html     = f"<html><body><p>Results: {_MARKER}</p></body></html>"

    result = benchmark(analyzer.analyze, html, _MARKER)
    assert result.reflected


def test_bench_reflection_script_string(benchmark) -> None:
    """Reflection analysis on a JavaScript string context."""
    analyzer = ReflectionAnalyzer()
    html     = f"<html><body><script>var q = '{_MARKER}';</script></body></html>"

    result = benchmark(analyzer.analyze, html, _MARKER)
    assert result.reflected


def test_bench_reflection_event_handler(benchmark) -> None:
    """Reflection analysis on an event-handler attribute (highest confidence)."""
    analyzer = ReflectionAnalyzer()
    html     = f'<html><body><img src=x onerror="alert({_MARKER})"></body></html>'

    result = benchmark(analyzer.analyze, html, _MARKER)
    assert result.reflected


def test_bench_reflection_no_match(benchmark) -> None:
    """Reflection analysis when marker is absent (baseline negative case)."""
    analyzer = ReflectionAnalyzer()
    html     = "<html><body><p>Nothing here.</p></body></html>"

    result = benchmark(analyzer.analyze, html, _MARKER)
    assert not result.reflected


def test_bench_reflection_large_page(benchmark) -> None:
    """Reflection analysis on a ~50 KB HTML page with marker buried in the middle."""
    analyzer = ReflectionAnalyzer()
    filler   = "<p>" + "A" * 100 + "</p>\n"
    html     = (
        "<html><body>"
        + filler * 200
        + f"<p>{_MARKER}</p>"
        + filler * 200
        + "</body></html>"
    )

    result = benchmark(analyzer.analyze, html, _MARKER)
    assert result.reflected


def test_bench_reflection_all_contexts(benchmark) -> None:
    """Cycle through all eight HTML contexts; reports aggregate throughput."""
    analyzer = ReflectionAnalyzer()
    samples  = _HTML_CONTEXTS

    def run_all():
        results = []
        for html, _ in samples:
            results.append(analyzer.analyze(html, _MARKER))
        return results

    results = benchmark(run_all)
    assert all(r.reflected for r in results)


# ---------------------------------------------------------------------------
# End-to-end scan speed benchmarks
# ---------------------------------------------------------------------------


def test_bench_scan_single_param(benchmark, bench_loop) -> None:
    """End-to-end async scan: one URL, one parameter, stops at first hit."""
    cfg      = _test_config()
    http     = _reflective_http()
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

    async def _scan():
        return await Scanner(cfg, http).scan_url("https://example.com/?q=test", payloads)

    result = benchmark(lambda: bench_loop.run_until_complete(_scan()))
    assert result.payloads_tested >= 1


def test_bench_scan_multi_param(benchmark, bench_loop) -> None:
    """End-to-end scan across five query parameters simultaneously."""
    cfg      = _test_config()
    http     = _reflective_http()
    payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
    url      = "https://example.com/search?q=a&name=b&id=1&page=1&sort=asc"

    async def _scan():
        return await Scanner(cfg, http).scan_url(url, payloads)

    result = benchmark(lambda: bench_loop.run_until_complete(_scan()))
    assert result.parameters_tested == 5


def test_bench_payload_throughput(benchmark, bench_loop) -> None:
    """
    Payload throughput: how many payloads per second the scanner can process.

    Uses a non-reflective server so the scanner tests ALL payloads rather than
    stopping at the first hit, giving a true throughput measurement.
    """
    cfg      = _test_config()
    http     = _non_reflective_http()
    # 20 payloads, none will reflect → all 20 get tested
    payloads = ["<script>alert(1)</script>"] * 20

    async def _scan():
        return await Scanner(cfg, http).scan_url("https://example.com/?q=test", payloads)

    result = benchmark(lambda: bench_loop.run_until_complete(_scan()))
    # All 20 payloads should be tested since none trigger a finding
    assert result.payloads_tested == 20
    benchmark.extra_info["payloads_tested"] = result.payloads_tested


def test_bench_scan_with_reflection_analysis(benchmark, bench_loop) -> None:
    """
    Combined scan + analysis pipeline: measures the full probe→reflect→analyze cycle.
    """
    cfg      = _test_config()
    http     = _reflective_http()
    payloads = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "';alert(1)//",
        '"><script>alert(1)</script>',
    ]

    async def _scan():
        return await Scanner(cfg, http).scan_url("https://example.com/?q=test", payloads)

    result = benchmark(lambda: bench_loop.run_until_complete(_scan()))
    assert result.findings or result.payloads_tested >= 1


# ---------------------------------------------------------------------------
# BenchmarkSummary — standalone baseline comparison utility
# ---------------------------------------------------------------------------


@dataclass
class BenchmarkMetric:
    """Timing statistics for a single benchmark."""
    name:       str
    mean_ms:    float
    min_ms:     float
    max_ms:     float
    stddev_ms:  float
    iterations: int
    extra:      dict[str, Any] = field(default_factory=dict)


@dataclass
class BenchmarkSummary:
    """
    Serialisable summary of a complete benchmark run.

    Save a baseline after an initial run, then compare subsequent runs to
    detect performance regressions before merging changes.

    Usage::

        # Save current run as baseline
        summary = BenchmarkSummary.capture(metrics)
        summary.save("tests/benchmarks/baselines/v1.json")

        # Compare a new run against the saved baseline
        new_summary = BenchmarkSummary.capture(new_metrics)
        delta = new_summary.compare("tests/benchmarks/baselines/v1.json")
        print(delta.report())
        if delta.has_regressions:
            raise RuntimeError("Performance regression detected")
    """

    recorded_at:       str
    framework_version: str
    metrics:           list[BenchmarkMetric] = field(default_factory=list)

    @classmethod
    def capture(
        cls,
        metrics: list[BenchmarkMetric],
        framework_version: str = "1.0.0",
    ) -> "BenchmarkSummary":
        return cls(
            recorded_at=datetime.now(timezone.utc).isoformat(),
            framework_version=framework_version,
            metrics=metrics,
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def save(self, path: str | Path) -> None:
        dest = Path(path)
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(
            json.dumps(
                {
                    "recorded_at":       self.recorded_at,
                    "framework_version": self.framework_version,
                    "metrics":           [asdict(m) for m in self.metrics],
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> "BenchmarkSummary":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(
            recorded_at=data["recorded_at"],
            framework_version=data["framework_version"],
            metrics=[BenchmarkMetric(**m) for m in data["metrics"]],
        )

    # ------------------------------------------------------------------
    # Comparison
    # ------------------------------------------------------------------

    def compare(self, baseline_path: str | Path) -> "BenchmarkDelta":
        baseline     = BenchmarkSummary.load(baseline_path)
        baseline_map = {m.name: m for m in baseline.metrics}
        current_map  = {m.name: m for m in self.metrics}
        deltas: list[dict[str, Any]] = []

        for name, cur in current_map.items():
            if name not in baseline_map:
                deltas.append({"name": name, "status": "new"})
                continue
            base = baseline_map[name]
            pct  = (
                (cur.mean_ms - base.mean_ms) / base.mean_ms * 100
                if base.mean_ms else 0.0
            )
            deltas.append({
                "name":        name,
                "status":      (
                    "regression"  if pct >  10 else
                    "improvement" if pct < -5  else
                    "stable"
                ),
                "baseline_ms": base.mean_ms,
                "current_ms":  cur.mean_ms,
                "change_pct":  round(pct, 1),
            })

        for name in baseline_map:
            if name not in current_map:
                deltas.append({"name": name, "status": "removed"})

        return BenchmarkDelta(
            baseline_recorded_at=baseline.recorded_at,
            current_recorded_at=self.recorded_at,
            deltas=deltas,
        )


@dataclass
class BenchmarkDelta:
    """Comparison result between a current run and a saved baseline."""
    baseline_recorded_at: str
    current_recorded_at:  str
    deltas:               list[dict[str, Any]]

    @property
    def has_regressions(self) -> bool:
        return any(d["status"] == "regression" for d in self.deltas)

    def report(self) -> str:
        lines = [
            "Benchmark Comparison Report",
            f"  Baseline : {self.baseline_recorded_at}",
            f"  Current  : {self.current_recorded_at}",
            "",
        ]
        for d in self.deltas:
            status = d["status"]
            name   = d["name"]
            if status == "new":
                lines.append(f"  [NEW     ] {name}")
            elif status == "removed":
                lines.append(f"  [REMOVED ] {name}")
            else:
                pct   = d["change_pct"]
                arrow = "↑" if pct > 0 else ("↓" if pct < 0 else "→")
                tag   = f"[{status.upper():^10}]"
                lines.append(
                    f"  {tag} {name:<50s} "
                    f"{d['baseline_ms']:7.2f}ms → {d['current_ms']:7.2f}ms  "
                    f"{arrow} {abs(pct):5.1f}%"
                )
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# BenchmarkSummary unit tests
# ---------------------------------------------------------------------------


class TestBenchmarkSummary:
    def test_capture_sets_recorded_at(self) -> None:
        s = BenchmarkSummary.capture([])
        assert s.recorded_at != ""

    def test_save_and_load_round_trips(self, tmp_path: Path) -> None:
        metrics = [BenchmarkMetric(
            name="test_bench", mean_ms=1.5, min_ms=1.0,
            max_ms=2.0, stddev_ms=0.2, iterations=100,
        )]
        s = BenchmarkSummary.capture(metrics)
        dest = tmp_path / "summary.json"
        s.save(dest)
        loaded = BenchmarkSummary.load(dest)
        assert len(loaded.metrics) == 1
        assert loaded.metrics[0].name == "test_bench"
        assert loaded.metrics[0].mean_ms == 1.5

    def test_compare_detects_regression(self, tmp_path: Path) -> None:
        baseline_metrics = [BenchmarkMetric(
            name="slow_bench", mean_ms=10.0, min_ms=9.0,
            max_ms=11.0, stddev_ms=0.5, iterations=50,
        )]
        baseline = BenchmarkSummary.capture(baseline_metrics)
        baseline.save(tmp_path / "baseline.json")

        # Current run is 50% slower → regression
        current_metrics = [BenchmarkMetric(
            name="slow_bench", mean_ms=15.0, min_ms=14.0,
            max_ms=16.0, stddev_ms=0.5, iterations=50,
        )]
        current = BenchmarkSummary.capture(current_metrics)
        delta = current.compare(tmp_path / "baseline.json")

        assert delta.has_regressions
        reg = next(d for d in delta.deltas if d["name"] == "slow_bench")
        assert reg["status"] == "regression"
        assert reg["change_pct"] == 50.0

    def test_compare_detects_improvement(self, tmp_path: Path) -> None:
        baseline_metrics = [BenchmarkMetric(
            name="fast_bench", mean_ms=10.0, min_ms=9.0,
            max_ms=11.0, stddev_ms=0.5, iterations=50,
        )]
        baseline = BenchmarkSummary.capture(baseline_metrics)
        baseline.save(tmp_path / "baseline.json")

        # Current run is 30% faster → improvement
        current_metrics = [BenchmarkMetric(
            name="fast_bench", mean_ms=7.0, min_ms=6.5,
            max_ms=7.5, stddev_ms=0.2, iterations=50,
        )]
        current = BenchmarkSummary.capture(current_metrics)
        delta = current.compare(tmp_path / "baseline.json")

        assert not delta.has_regressions
        imp = next(d for d in delta.deltas if d["name"] == "fast_bench")
        assert imp["status"] == "improvement"

    def test_compare_marks_new_benchmark(self, tmp_path: Path) -> None:
        baseline = BenchmarkSummary.capture([])
        baseline.save(tmp_path / "baseline.json")

        current = BenchmarkSummary.capture([BenchmarkMetric(
            name="brand_new", mean_ms=5.0, min_ms=4.5,
            max_ms=5.5, stddev_ms=0.1, iterations=10,
        )])
        delta = current.compare(tmp_path / "baseline.json")

        new_items = [d for d in delta.deltas if d["status"] == "new"]
        assert len(new_items) == 1
        assert new_items[0]["name"] == "brand_new"

    def test_compare_marks_removed_benchmark(self, tmp_path: Path) -> None:
        baseline = BenchmarkSummary.capture([BenchmarkMetric(
            name="old_bench", mean_ms=5.0, min_ms=4.5,
            max_ms=5.5, stddev_ms=0.1, iterations=10,
        )])
        baseline.save(tmp_path / "baseline.json")

        current = BenchmarkSummary.capture([])
        delta = current.compare(tmp_path / "baseline.json")

        removed = [d for d in delta.deltas if d["status"] == "removed"]
        assert len(removed) == 1

    def test_report_string_contains_benchmark_name(self, tmp_path: Path) -> None:
        metrics = [BenchmarkMetric(
            name="my_test_bench", mean_ms=1.0, min_ms=0.9,
            max_ms=1.1, stddev_ms=0.05, iterations=20,
        )]
        baseline = BenchmarkSummary.capture(metrics)
        baseline.save(tmp_path / "b.json")
        current = BenchmarkSummary.capture(metrics)
        delta   = current.compare(tmp_path / "b.json")
        report  = delta.report()
        assert "my_test_bench" in report

    def test_stable_benchmark_has_no_regressions(self, tmp_path: Path) -> None:
        metrics = [BenchmarkMetric(
            name="stable_bench", mean_ms=5.0, min_ms=4.5,
            max_ms=5.5, stddev_ms=0.2, iterations=50,
        )]
        BenchmarkSummary.capture(metrics).save(tmp_path / "b.json")
        # Same timings — should be "stable"
        current = BenchmarkSummary.capture(metrics)
        delta   = current.compare(tmp_path / "b.json")
        assert not delta.has_regressions
