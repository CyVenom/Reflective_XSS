"""
Comprehensive tests for the advanced reflection analysis engine.

Coverage:
- ConfidenceLevel ordering and IntEnum contract
- EncodingFingerprint: no encoding, HTML entity, URL-encoded, JS-escaped,
  double-encoded, filtered, mixed
- ReflectionContext detection via DOM parsing for every context type
- _ScriptContextClassifier: bare code, string literals (all quote types),
  line comments, block comments, escape sequences
- Confidence scoring per context × encoding combination
- Multiple occurrences — best (highest confidence) wins
- False positive suppression: over-occurrence, baseline hit
- Response diffing: marker in new vs pre-existing content
- ReflectionResult immutability and bool contract
- Regex fallback path (malformed HTML)
- ReflectionAnalyzer.analyze() end-to-end with payload argument
"""

from __future__ import annotations

import pytest

from core.reflection import (
    ConfidenceLevel,
    ReflectionAnalyzer,
    ReflectionContext,
    ReflectionOccurrence,
    ReflectionResult,
    _DomContextDetector,
    _EncodingAnalyzer,
    _FalsePositiveDetector,
    _ResponseDiffer,
    _ScriptContextClassifier,
)

MARKER = "AbCdEfGh"


@pytest.fixture
def analyzer() -> ReflectionAnalyzer:
    return ReflectionAnalyzer()


@pytest.fixture
def enc() -> _EncodingAnalyzer:
    return _EncodingAnalyzer()


@pytest.fixture
def differ() -> _ResponseDiffer:
    return _ResponseDiffer()


# ---------------------------------------------------------------------------
# ConfidenceLevel
# ---------------------------------------------------------------------------


class TestConfidenceLevel:
    def test_ordering(self) -> None:
        assert ConfidenceLevel.LOW < ConfidenceLevel.MEDIUM
        assert ConfidenceLevel.MEDIUM < ConfidenceLevel.HIGH
        assert ConfidenceLevel.HIGH < ConfidenceLevel.CRITICAL

    def test_int_enum(self) -> None:
        assert int(ConfidenceLevel.LOW) == 1
        assert int(ConfidenceLevel.CRITICAL) == 4

    def test_name_strings(self) -> None:
        assert ConfidenceLevel.CRITICAL.name == "CRITICAL"
        assert ConfidenceLevel.LOW.name == "LOW"

    def test_max_returns_critical(self) -> None:
        levels = [ConfidenceLevel.LOW, ConfidenceLevel.CRITICAL, ConfidenceLevel.MEDIUM]
        assert max(levels) == ConfidenceLevel.CRITICAL


# ---------------------------------------------------------------------------
# ReflectionResult contract
# ---------------------------------------------------------------------------


class TestReflectionResult:
    def test_bool_false_when_not_reflected(self) -> None:
        r = ReflectionResult(reflected=False, marker=MARKER)
        assert not bool(r)

    def test_bool_true_when_reflected(self) -> None:
        r = ReflectionResult(reflected=True, marker=MARKER)
        assert bool(r)

    def test_bool_false_when_false_positive(self) -> None:
        r = ReflectionResult(reflected=True, marker=MARKER, is_false_positive=True)
        assert not bool(r)

    def test_frozen_immutable(self) -> None:
        r = ReflectionResult(reflected=True, marker=MARKER)
        with pytest.raises((AttributeError, TypeError)):
            r.reflected = False  # type: ignore[misc]

    def test_severity_property_maps_confidence(self) -> None:
        r = ReflectionResult(
            reflected=True, marker=MARKER, confidence=ConfidenceLevel.CRITICAL
        )
        assert r.severity == "CRITICAL"

    def test_default_occurrences_empty_tuple(self) -> None:
        r = ReflectionResult(reflected=False, marker=MARKER)
        assert r.occurrences == ()

    def test_default_encoding_none(self) -> None:
        r = ReflectionResult(reflected=False, marker=MARKER)
        assert r.encoding is None


# ---------------------------------------------------------------------------
# EncodingAnalyzer — fingerprinting
# ---------------------------------------------------------------------------


class TestEncodingAnalyzer:
    def test_no_encoding_preserves_all_chars(self, enc: _EncodingAnalyzer) -> None:
        payload = f"<script>alert({MARKER})</script>"
        raw = f"<p>{payload}</p>"
        fp = enc.analyze(raw, MARKER, payload)
        assert "<" in fp.dangerous_chars_preserved
        assert ">" in fp.dangerous_chars_preserved
        assert "(" in fp.dangerous_chars_preserved
        assert "none" in fp.encoding_types

    def test_html_entity_encoding_detected(self, enc: _EncodingAnalyzer) -> None:
        payload = f"<script>alert({MARKER})</script>"
        raw = f"<p>&lt;script&gt;alert({MARKER})&lt;/script&gt;</p>"
        fp = enc.analyze(raw, MARKER, payload)
        assert "html_entity" in fp.encoding_types
        assert "<" in fp.dangerous_chars_encoded
        assert ">" in fp.dangerous_chars_encoded

    def test_url_encoding_detected(self, enc: _EncodingAnalyzer) -> None:
        payload = f"<img src=x onerror=alert({MARKER})>"
        raw = f"value=%3Cimg+src%3Dx+onerror%3Dalert({MARKER})%3E"
        fp = enc.analyze(raw, MARKER, payload)
        assert "url_encoded" in fp.encoding_types

    def test_js_escaped_encoding_detected(self, enc: _EncodingAnalyzer) -> None:
        payload = f"<{MARKER}>"
        raw = f"var x = '\\u003c{MARKER}\\u003e';"
        fp = enc.analyze(raw, MARKER, payload)
        assert "js_escaped" in fp.encoding_types

    def test_breakout_possible_when_preserved(self, enc: _EncodingAnalyzer) -> None:
        raw = f"<p>Hello {MARKER} world</p>"
        payload = f"<{MARKER}>"
        fp = enc.analyze(raw, MARKER, payload)
        assert fp.breakout_possible is True

    def test_no_breakout_when_fully_encoded(self, enc: _EncodingAnalyzer) -> None:
        payload = f"<{MARKER}>"
        raw = f"<p>&lt;{MARKER}&gt;</p>"
        fp = enc.analyze(raw, MARKER, payload)
        assert fp.breakout_possible is False

    def test_filtered_chars_detected(self, enc: _EncodingAnalyzer) -> None:
        # Payload has < but response has neither < nor &lt; anywhere near the marker
        payload = f"<b>{MARKER}</b>"
        raw = f"b{MARKER}b"   # tags stripped entirely, no structural HTML either
        fp = enc.analyze(raw, MARKER, payload)
        assert "<" in fp.dangerous_chars_filtered

    def test_exploitation_difficulty_trivial(self, enc: _EncodingAnalyzer) -> None:
        payload = f"<>{MARKER}\"'()"
        raw = payload
        fp = enc.analyze(raw, MARKER, payload)
        assert fp.exploitation_difficulty in ("TRIVIAL", "EASY")

    def test_exploitation_difficulty_none_when_all_filtered(
        self, enc: _EncodingAnalyzer
    ) -> None:
        payload = f"<script>alert({MARKER})</script>"
        # Server strips the payload entirely — only plain text remains, no HTML tags
        raw = f"plain text {MARKER} here"
        fp = enc.analyze(raw, MARKER, payload)
        # < ( ) > all came from payload but none appear in raw context
        assert fp.exploitation_difficulty in ("NONE", "HARD")

    def test_double_encoding_detected(self, enc: _EncodingAnalyzer) -> None:
        # &amp;lt; is a double-encoded <
        raw = f"<p>&amp;lt;{MARKER}&amp;gt;</p>"
        fp = enc.analyze(raw, MARKER, None)
        assert "double_encoded" in fp.encoding_types

    def test_raw_context_window_captured(self, enc: _EncodingAnalyzer) -> None:
        prefix = "X" * 200
        suffix = "Y" * 200
        raw = f"{prefix}{MARKER}{suffix}"
        fp = enc.analyze(raw, MARKER, None)
        assert MARKER in fp.raw_context
        # Window should not include the full 200-char prefix
        assert len(fp.raw_context) < len(raw)


# ---------------------------------------------------------------------------
# ScriptContextClassifier
# ---------------------------------------------------------------------------


class TestScriptContextClassifier:
    @pytest.fixture
    def cls(self) -> _ScriptContextClassifier:
        return _ScriptContextClassifier()

    def test_bare_code(self, cls: _ScriptContextClassifier) -> None:
        src = f"var x = {MARKER};"
        ctx, quote = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_BLOCK
        assert quote is None

    def test_double_quoted_string(self, cls: _ScriptContextClassifier) -> None:
        src = f'var x = "{MARKER}";'
        ctx, quote = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_STRING
        assert quote == '"'

    def test_single_quoted_string(self, cls: _ScriptContextClassifier) -> None:
        src = f"var x = '{MARKER}';"
        ctx, quote = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_STRING
        assert quote == "'"

    def test_template_literal(self, cls: _ScriptContextClassifier) -> None:
        src = f"var x = `{MARKER}`;"
        ctx, quote = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_STRING
        assert quote == "`"

    def test_after_line_comment_end(self, cls: _ScriptContextClassifier) -> None:
        # Marker is on the line AFTER the comment — bare code
        src = f"// comment\nvar x = {MARKER};"
        ctx, _ = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_BLOCK

    def test_escaped_quote_does_not_close_string(
        self, cls: _ScriptContextClassifier
    ) -> None:
        # The \' does not end the string
        src = f"var x = 'it\\'s {MARKER}';"
        ctx, quote = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_STRING
        assert quote == "'"

    def test_block_comment_before_marker(self, cls: _ScriptContextClassifier) -> None:
        src = f"/* comment */ var x = {MARKER};"
        ctx, _ = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_BLOCK

    def test_nested_quotes_do_not_confuse_state(
        self, cls: _ScriptContextClassifier
    ) -> None:
        # Single quote inside double-quoted string — state stays "in double string"
        src = f'var x = "it\'s fine"; var y = {MARKER};'
        ctx, _ = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_BLOCK

    def test_marker_not_in_script_returns_block(
        self, cls: _ScriptContextClassifier
    ) -> None:
        src = "var x = 1;"
        ctx, quote = cls.classify(src, MARKER)
        assert ctx == ReflectionContext.SCRIPT_BLOCK
        assert quote is None


# ---------------------------------------------------------------------------
# ReflectionAnalyzer — context detection
# ---------------------------------------------------------------------------


class TestContextDetection:
    """End-to-end context detection via ReflectionAnalyzer.analyze()."""

    def test_no_reflection(self, analyzer: ReflectionAnalyzer) -> None:
        result = analyzer.analyze("<html><body>nothing</body></html>", MARKER)
        assert not result
        assert result.reflected is False

    def test_html_text_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<html><body><p>Hello {MARKER} world</p></body></html>"
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.HTML_TEXT

    def test_script_bare_code_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<script>var x = {MARKER};</script>"
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.SCRIPT_BLOCK

    def test_script_string_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<script>var x = '{MARKER}';</script>"
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.SCRIPT_STRING

    def test_script_double_quoted_string(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<script>var x = "{MARKER}";</script>'
        result = analyzer.analyze(html, MARKER)
        assert result.context == ReflectionContext.SCRIPT_STRING
        assert result.occurrences[0].js_string_quote == '"'

    def test_event_handler_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<img src=x onerror="alert({MARKER})">'
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.HTML_ATTRIBUTE_EVENT

    def test_event_handler_unquoted(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<img src=x onerror=alert({MARKER})>"
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.HTML_ATTRIBUTE_EVENT

    def test_href_url_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<a href="https://example.com/?q={MARKER}">click</a>'
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.HTML_ATTRIBUTE_URL

    def test_src_url_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<img src="https://example.com/{MARKER}.png">'
        result = analyzer.analyze(html, MARKER)
        assert result.context == ReflectionContext.HTML_ATTRIBUTE_URL

    def test_javascript_uri_in_href(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<a href="javascript:alert({MARKER})">click</a>'
        result = analyzer.analyze(html, MARKER)
        assert result.context == ReflectionContext.HTML_ATTRIBUTE_URL
        assert result.confidence == ConfidenceLevel.CRITICAL

    def test_generic_attribute_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<input placeholder="{MARKER}">'
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.HTML_ATTRIBUTE

    def test_style_block_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<style>/* {MARKER} */</style>"
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.STYLE_BLOCK

    def test_html_comment_context(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<!-- {MARKER} --><html></html>"
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.HTML_COMMENT

    def test_case_insensitive_script_tag(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<SCRIPT>{MARKER}</SCRIPT>"
        result = analyzer.analyze(html, MARKER)
        assert result
        assert result.context == ReflectionContext.SCRIPT_BLOCK

    def test_snippet_captured(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<p>prefix {MARKER} suffix</p>"
        result = analyzer.analyze(html, MARKER)
        assert result.snippet is not None
        assert MARKER in result.snippet

    def test_occurrences_returned(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<script>var x = '{MARKER}';</script>"
        result = analyzer.analyze(html, MARKER)
        assert len(result.occurrences) >= 1

    def test_occurrence_has_tag_name(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<img src=x onerror="alert({MARKER})">'
        result = analyzer.analyze(html, MARKER)
        occ = result.occurrences[0]
        assert occ.tag_name == "img"

    def test_occurrence_has_attribute_name(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<img src=x onerror="alert({MARKER})">'
        result = analyzer.analyze(html, MARKER)
        occ = result.occurrences[0]
        assert occ.attribute_name == "onerror"

    def test_in_js_string_flag(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<script>var x = '{MARKER}';</script>"
        result = analyzer.analyze(html, MARKER)
        occ = result.occurrences[0]
        assert occ.in_js_string is True
        assert occ.js_string_quote == "'"

    def test_exploitation_notes_populated(self, analyzer: ReflectionAnalyzer) -> None:
        html = f'<img src=x onerror="alert({MARKER})">'
        result = analyzer.analyze(html, MARKER)
        assert result.occurrences[0].exploitation_notes != ""


# ---------------------------------------------------------------------------
# Confidence scoring
# ---------------------------------------------------------------------------


class TestConfidenceScoring:
    def test_bare_script_unencoded_is_critical(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        payload = f"<script>alert({MARKER})</script>"
        html = f"<script>alert({MARKER})</script>"
        result = analyzer.analyze(html, MARKER, payload=payload)
        assert result.confidence >= ConfidenceLevel.HIGH

    def test_event_handler_with_parens_is_critical(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        payload = f"<img src=x onerror=alert({MARKER})>"
        html = f'<img src=x onerror="alert({MARKER})">'
        result = analyzer.analyze(html, MARKER, payload=payload)
        assert result.confidence == ConfidenceLevel.CRITICAL

    def test_html_comment_is_low(self, analyzer: ReflectionAnalyzer) -> None:
        html = f"<!-- {MARKER} -->"
        result = analyzer.analyze(html, MARKER)
        assert result.confidence == ConfidenceLevel.LOW

    def test_html_text_with_encoded_angle_brackets_is_low(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        payload = f"<script>alert({MARKER})</script>"
        html = f"<p>&lt;script&gt;alert({MARKER})&lt;/script&gt;</p>"
        result = analyzer.analyze(html, MARKER, payload=payload)
        assert result.confidence == ConfidenceLevel.LOW

    def test_html_text_with_unencoded_angle_brackets_is_high(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        payload = f"<b>{MARKER}</b>"
        html = f"<p><b>{MARKER}</b></p>"
        result = analyzer.analyze(html, MARKER, payload=payload)
        assert result.confidence >= ConfidenceLevel.HIGH

    def test_script_string_with_quote_char_is_high(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        # The enclosing quote is preserved — breakout is easy
        payload = f"'{MARKER}'"
        html = f"<script>var x = '{MARKER}';</script>"
        result = analyzer.analyze(html, MARKER, payload=payload)
        assert result.confidence >= ConfidenceLevel.MEDIUM

    def test_multiple_occurrences_picks_highest(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        # Marker appears in both a comment (LOW) and a script block (higher)
        html = (
            f"<!-- {MARKER} -->"
            f"<script>var x = {MARKER};</script>"
        )
        result = analyzer.analyze(html, MARKER)
        assert result.context == ReflectionContext.SCRIPT_BLOCK

    def test_severity_property_matches_confidence(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        html = f"<script>var x = {MARKER};</script>"
        result = analyzer.analyze(html, MARKER)
        assert result.severity == result.confidence.name


# ---------------------------------------------------------------------------
# False positive detection
# ---------------------------------------------------------------------------


class TestFalsePositiveDetection:
    def test_marker_in_baseline_is_false_positive(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        baseline = f"<html><body>{MARKER}</body></html>"
        response = f"<html><body>{MARKER}</body></html>"
        result = analyzer.analyze(response, MARKER, baseline_text=baseline)
        assert result.is_false_positive is True
        assert not bool(result)

    def test_marker_not_in_baseline_is_not_false_positive(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        baseline = "<html><body>clean page</body></html>"
        response = f"<html><body>{MARKER}</body></html>"
        result = analyzer.analyze(response, MARKER, baseline_text=baseline)
        assert result.is_false_positive is False
        assert bool(result)

    def test_excessive_occurrences_flagged(self) -> None:
        fp = _FalsePositiveDetector()
        # Marker appears 10 times — static content heuristic
        raw = (f"<p>{MARKER}</p>" * 10)
        is_fp = fp.check(raw, MARKER, [], baseline_text=None)
        assert is_fp is True

    def test_normal_occurrence_count_passes(self) -> None:
        fp = _FalsePositiveDetector()
        raw = f"<p>{MARKER}</p>"
        is_fp = fp.check(raw, MARKER, [], baseline_text=None)
        assert is_fp is False


# ---------------------------------------------------------------------------
# Response differ
# ---------------------------------------------------------------------------


class TestResponseDiffer:
    def test_new_line_detected(self, differ: _ResponseDiffer) -> None:
        baseline = "<p>Hello</p>"
        response = f"<p>Hello</p>\n<p>{MARKER}</p>"
        new = differ.new_lines(baseline, response)
        assert any(MARKER in line for line in new)

    def test_unchanged_line_not_in_new(self, differ: _ResponseDiffer) -> None:
        line = "<p>Static content</p>"
        baseline = line
        response = line
        new = differ.new_lines(baseline, response)
        assert line not in new

    def test_marker_confined_to_new_content_true(
        self, differ: _ResponseDiffer
    ) -> None:
        baseline = "<p>safe</p>"
        response = f"<p>safe</p>\n<p>{MARKER}</p>"
        assert differ.marker_confined_to_new_content(baseline, response, MARKER) is True

    def test_marker_in_baseline_returns_false(self, differ: _ResponseDiffer) -> None:
        both = f"<p>{MARKER}</p>"
        assert differ.marker_confined_to_new_content(both, both, MARKER) is False

    def test_diff_integration_suppresses_fp(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        # Marker is in both baseline and response → false positive
        baseline = f"<p>{MARKER}</p>"
        response = f"<p>{MARKER}</p><p>extra</p>"
        result = analyzer.analyze(response, MARKER, baseline_text=baseline)
        assert result.is_false_positive is True


# ---------------------------------------------------------------------------
# End-to-end with payload argument
# ---------------------------------------------------------------------------


class TestEndToEndWithPayload:
    def test_payload_improves_encoding_analysis(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        payload = f"<script>alert({MARKER})</script>"
        # Server HTML-encodes the angle brackets
        response = f"<p>&lt;script&gt;alert({MARKER})&lt;/script&gt;</p>"
        result = analyzer.analyze(response, MARKER, payload=payload)
        assert result.reflected is True
        assert result.encoding is not None
        assert "html_entity" in result.encoding.encoding_types
        # < and > should be in encoded list, not preserved
        assert "<" not in result.encoding.dangerous_chars_preserved

    def test_unencoded_event_handler_payload(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        payload = f"<img src=x onerror=alert({MARKER})>"
        response = f'<img src=x onerror="alert({MARKER})">'
        result = analyzer.analyze(response, MARKER, payload=payload)
        assert result.context == ReflectionContext.HTML_ATTRIBUTE_EVENT
        assert result.confidence == ConfidenceLevel.CRITICAL

    def test_encoding_fingerprint_on_result(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        response = f"<p>Hello {MARKER}</p>"
        result = analyzer.analyze(response, MARKER, payload=f"Hello {MARKER}")
        assert result.encoding is not None
        assert isinstance(result.encoding.exploitation_difficulty, str)

    def test_analyze_returns_false_when_marker_absent(
        self, analyzer: ReflectionAnalyzer
    ) -> None:
        result = analyzer.analyze("<p>nothing</p>", "ZzZzZzZz")
        assert result.reflected is False
        assert not bool(result)
        assert result.snippet is None

    def test_diff_responses_utility(self, analyzer: ReflectionAnalyzer) -> None:
        baseline = "<p>line one</p>"
        response = f"<p>line one</p>\n<p>{MARKER}</p>"
        new_lines = analyzer.diff_responses(baseline, response)
        assert any(MARKER in l for l in new_lines)
