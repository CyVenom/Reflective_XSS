"""Unit tests for the reflection analysis engine."""

from __future__ import annotations

import pytest

from core.reflection import ReflectionAnalyzer, ReflectionContext, ReflectionResult


@pytest.fixture
def analyzer() -> ReflectionAnalyzer:
    return ReflectionAnalyzer()


class TestReflectionResult:
    def test_bool_true_when_reflected(self) -> None:
        r = ReflectionResult(reflected=True, marker="AbCdEfGh")
        assert bool(r) is True

    def test_bool_false_when_not_reflected(self) -> None:
        r = ReflectionResult(reflected=False, marker="AbCdEfGh")
        assert bool(r) is False

    def test_frozen_immutable(self) -> None:
        r = ReflectionResult(reflected=True, marker="X")
        with pytest.raises((AttributeError, TypeError)):
            r.reflected = False  # type: ignore[misc]


class TestReflectionAnalyzer:
    def test_no_reflection(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<html><body>Nothing here</body></html>"
        result = analyzer.analyze(html, "AbCdEfGh")
        assert not result
        assert result.reflected is False

    def test_reflection_in_body(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<html><body>Hello AbCdEfGh world</body></html>"
        result = analyzer.analyze(html, "AbCdEfGh")
        assert result
        assert result.reflected is True
        assert result.context == ReflectionContext.HTML_BODY

    def test_reflection_in_script_block(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<html><script>var x = 'AbCdEfGh';</script></html>"
        result = analyzer.analyze(html, "AbCdEfGh")
        assert result
        assert result.context == ReflectionContext.SCRIPT_BLOCK

    def test_reflection_in_style_block(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<html><style>/* AbCdEfGh */</style></html>"
        result = analyzer.analyze(html, "AbCdEfGh")
        assert result
        assert result.context == ReflectionContext.STYLE_BLOCK

    def test_reflection_in_html_attribute(self, analyzer: ReflectionAnalyzer) -> None:
        html = '<html><img src="x" alt="AbCdEfGh"></html>'
        result = analyzer.analyze(html, "AbCdEfGh")
        assert result
        assert result.context == ReflectionContext.HTML_ATTRIBUTE

    def test_reflection_in_comment(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<!-- AbCdEfGh --><html></html>"
        result = analyzer.analyze(html, "AbCdEfGh")
        assert result
        assert result.context == ReflectionContext.COMMENT

    def test_snippet_contains_marker(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<html><body>prefix AbCdEfGh suffix</body></html>"
        result = analyzer.analyze(html, "AbCdEfGh")
        assert result.snippet is not None
        assert "AbCdEfGh" in result.snippet

    def test_marker_not_in_response(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<html><body>alert(1)</body></html>"
        result = analyzer.analyze(html, "ZzZzZzZz")
        assert not result
        assert result.snippet is None

    def test_multiline_script_block(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<script>\nvar a = 1;\nvar b = 'AbCdEfGh';\n</script>"
        result = analyzer.analyze(html, "AbCdEfGh")
        assert result.context == ReflectionContext.SCRIPT_BLOCK

    def test_case_insensitive_tag_detection(self, analyzer: ReflectionAnalyzer) -> None:
        html = "<SCRIPT>AbCdEfGh</SCRIPT>"
        result = analyzer.analyze(html, "AbCdEfGh")
        # Should still detect as SCRIPT_BLOCK due to re.IGNORECASE
        assert result
        assert result.context == ReflectionContext.SCRIPT_BLOCK
