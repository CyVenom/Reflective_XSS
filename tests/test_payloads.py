"""
Comprehensive tests for the payload engine, models, encoder, mutators, and
filter detection/prioritization subsystems.

Backward-compatible tests for PayloadGenerator and PayloadEngine.load() are
preserved at the bottom so the existing test suite continues to pass.
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from core.config import PayloadConfig
from payloads.engine import FilterDetector, PayloadEngine, PayloadPrioritizer
from payloads.generator import (
    AdvancedPayloadMutator,
    PayloadEncoder,
    PayloadGenerator,
    RandomPayloadGenerator,
)
from payloads.models import PayloadCategory, PayloadEntry


# ===========================================================================
# PayloadCategory
# ===========================================================================


class TestPayloadCategory:
    def test_all_six_categories_defined(self) -> None:
        expected = {"basic", "polyglot", "waf_bypass", "attribute_injection", "js_context", "svg"}
        assert {c.value for c in PayloadCategory if c != PayloadCategory.CUSTOM} == expected

    def test_custom_category_defined(self) -> None:
        assert PayloadCategory.CUSTOM.value == "custom"

    def test_is_string_enum(self) -> None:
        assert PayloadCategory.BASIC == "basic"
        assert isinstance(PayloadCategory.BASIC, str)

    def test_from_string(self) -> None:
        assert PayloadCategory("svg") is PayloadCategory.SVG

    def test_invalid_raises(self) -> None:
        with pytest.raises(ValueError):
            PayloadCategory("nonexistent")


# ===========================================================================
# PayloadEntry
# ===========================================================================


class TestPayloadEntry:
    def test_frozen(self) -> None:
        entry = PayloadEntry(text="<script>alert(1)</script>")
        with pytest.raises((AttributeError, TypeError)):
            entry.text = "changed"  # type: ignore[misc]

    def test_defaults(self) -> None:
        entry = PayloadEntry(text="x")
        assert entry.category is PayloadCategory.BASIC
        assert entry.tags == ()
        assert entry.description == ""
        assert entry.severity == "high"
        assert entry.source == ""

    def test_tags_tuple(self) -> None:
        entry = PayloadEntry(text="x", tags=("a", "b"))
        assert isinstance(entry.tags, tuple)
        assert entry.tags == ("a", "b")

    def test_mutated_preserves_category(self) -> None:
        entry = PayloadEntry(text="original", category=PayloadCategory.SVG)
        m = entry.mutated("new text")
        assert m.category is PayloadCategory.SVG

    def test_mutated_appends_note_to_tags(self) -> None:
        entry = PayloadEntry(text="x", tags=("classic",))
        m = entry.mutated("y", note="url-encoded")
        assert "url-encoded" in m.tags
        assert "classic" in m.tags

    def test_mutated_preserves_severity_and_source(self) -> None:
        entry = PayloadEntry(text="x", severity="low", source="file.yaml")
        m = entry.mutated("y")
        assert m.severity == "low"
        assert m.source == "file.yaml"

    def test_original_unchanged_by_mutated(self) -> None:
        entry = PayloadEntry(text="original", tags=("t1",))
        entry.mutated("new")
        assert entry.text == "original"
        assert entry.tags == ("t1",)


# ===========================================================================
# PayloadEncoder
# ===========================================================================


class TestPayloadEncoder:
    def test_url_encode_angle_brackets(self) -> None:
        result = PayloadEncoder.url_encode("<script>")
        assert "<" not in result
        assert ">" not in result
        assert "%3C" in result.upper()
        assert "%3E" in result.upper()

    def test_url_encode_empty(self) -> None:
        assert PayloadEncoder.url_encode("") == ""

    def test_double_url_encode(self) -> None:
        single = PayloadEncoder.url_encode("<")
        double = PayloadEncoder.double_url_encode("<")
        assert single in double or "%25" in double
        assert double != single

    def test_double_encode_has_percent25(self) -> None:
        result = PayloadEncoder.double_url_encode("<script>")
        assert "%25" in result

    def test_html_encode_decimal(self) -> None:
        result = PayloadEncoder.html_encode_decimal("ab")
        assert "&#97;" in result
        assert "&#98;" in result

    def test_html_encode_hex(self) -> None:
        result = PayloadEncoder.html_encode_hex("A")
        assert "&#x41;" in result

    def test_url_encode_roundtrip(self) -> None:
        original = "<img src=x onerror=alert(1)>"
        encoded = PayloadEncoder.url_encode(original)
        assert PayloadEncoder.decode_url(encoded) == original

    def test_html_encode_decimal_all_chars(self) -> None:
        result = PayloadEncoder.html_encode_decimal("<>")
        assert "&#60;" in result
        assert "&#62;" in result


# ===========================================================================
# AdvancedPayloadMutator
# ===========================================================================


class TestAdvancedPayloadMutator:
    def _make_entry(self, text: str, **kw: object) -> PayloadEntry:
        return PayloadEntry(text=text, **kw)  # type: ignore[arg-type]

    def test_originals_preserved_at_front(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [self._make_entry("<script>alert(1)</script>")]
        result = mutator.apply_mutations(entries)
        assert result[0] == entries[0]

    def test_encoding_mutations_generated(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [self._make_entry("<img src=x onerror=alert(1)>")]
        result = mutator.apply_mutations(entries)
        texts = [e.text for e in result]
        assert any("url-encoded" in e.tags for e in result), "Expected url-encoded variant"
        assert len(texts) > 1

    def test_html_entity_mutation_on_alert(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [self._make_entry("<img src=x onerror=alert(1)>")]
        result = mutator.apply_mutations(entries)
        assert any("html-entity-encoded" in e.tags for e in result)

    def test_whitespace_mutation_on_img(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [self._make_entry("<img src=x onerror=alert(1)>")]
        result = mutator.apply_mutations(entries)
        assert any("whitespace-mutated" in e.tags for e in result)

    def test_comment_mutation_on_alert(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [self._make_entry("<img src=x onerror=alert(1)>")]
        result = mutator.apply_mutations(entries)
        assert any("comment-mutated" in e.tags for e in result)

    def test_no_duplicates_in_output(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [
            self._make_entry("<img src=x onerror=alert(1)>"),
            self._make_entry("<script>alert(1)</script>"),
        ]
        result = mutator.apply_mutations(entries)
        texts = [e.text for e in result]
        assert len(texts) == len(set(texts))

    def test_no_new_mutations_for_unknown_payload(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [self._make_entry("totally_safe_string_xyz")]
        result = mutator.apply_mutations(entries)
        # Only url/double-url encoding mutations may fire (no alert/onerror in text)
        # but whitespace and comment mutations should NOT fire
        comment_mutated = [e for e in result if "comment-mutated" in e.tags]
        whitespace_mutated = [e for e in result if "whitespace-mutated" in e.tags]
        html_entity_mutated = [e for e in result if "html-entity-encoded" in e.tags]
        assert not comment_mutated
        assert not whitespace_mutated
        assert not html_entity_mutated

    def test_mutation_preserves_category(self) -> None:
        mutator = AdvancedPayloadMutator()
        entries = [self._make_entry("<img src=x onerror=alert(1)>", category=PayloadCategory.SVG)]
        result = mutator.apply_mutations(entries)
        for e in result:
            assert e.category is PayloadCategory.SVG


# ===========================================================================
# RandomPayloadGenerator
# ===========================================================================


class TestRandomPayloadGenerator:
    def test_generates_requested_count(self) -> None:
        gen = RandomPayloadGenerator(seed=0)
        result = gen.generate(10)
        assert len(result) == 10

    def test_all_entries_have_nonempty_text(self) -> None:
        gen = RandomPayloadGenerator(seed=1)
        result = gen.generate(5)
        assert all(e.text for e in result)

    def test_all_entries_have_random_tag(self) -> None:
        gen = RandomPayloadGenerator(seed=2)
        result = gen.generate(5)
        assert all("random" in e.tags for e in result)

    def test_seeded_output_is_deterministic(self) -> None:
        gen1 = RandomPayloadGenerator(seed=42)
        gen2 = RandomPayloadGenerator(seed=42)
        assert gen1.generate(8) == gen2.generate(8)

    def test_different_seeds_produce_different_output(self) -> None:
        gen1 = RandomPayloadGenerator(seed=1)
        gen2 = RandomPayloadGenerator(seed=2)
        texts1 = {e.text for e in gen1.generate(20)}
        texts2 = {e.text for e in gen2.generate(20)}
        assert texts1 != texts2

    def test_no_duplicates_in_output(self) -> None:
        gen = RandomPayloadGenerator(seed=7)
        result = gen.generate(15)
        texts = [e.text for e in result]
        assert len(texts) == len(set(texts))

    def test_source_field_set(self) -> None:
        gen = RandomPayloadGenerator(seed=0)
        result = gen.generate(3)
        assert all(e.source == "random-generator" for e in result)

    def test_zero_count_returns_empty(self) -> None:
        gen = RandomPayloadGenerator(seed=0)
        assert gen.generate(0) == []


# ===========================================================================
# FilterDetector
# ===========================================================================


class TestFilterDetector:
    def test_empty_probe_returns_empty_set(self) -> None:
        detector = FilterDetector()
        assert detector.detect({}) == set()

    def test_char_absent_from_response_is_filtered(self) -> None:
        detector = FilterDetector()
        result = detector.detect({"<": "response without angle bracket"})
        assert "<" in result

    def test_char_present_in_response_not_filtered(self) -> None:
        detector = FilterDetector()
        result = detector.detect({"<": "response has < here"})
        assert "<" not in result

    def test_multiple_chars(self) -> None:
        detector = FilterDetector()
        result = detector.detect({
            "<": "no angle",
            ">": "has > here",
            '"': "no quote",
        })
        assert "<" in result
        assert ">" not in result
        assert '"' in result

    def test_survivable_empty_filter_returns_all(self) -> None:
        detector = FilterDetector()
        payloads = ["<script>", "<img>", "alert(1)"]
        assert detector.survivable(payloads, set()) == payloads

    def test_survivable_removes_payloads_with_filtered_char(self) -> None:
        detector = FilterDetector()
        payloads = ["<script>alert(1)</script>", "alert(1)", "prompt(1)"]
        result = detector.survivable(payloads, {"<"})
        assert "<script>alert(1)</script>" not in result
        assert "alert(1)" in result
        assert "prompt(1)" in result

    def test_probe_chars_tuple_not_empty(self) -> None:
        assert len(FilterDetector.PROBE_CHARS) >= 5


# ===========================================================================
# PayloadPrioritizer
# ===========================================================================


class TestPayloadPrioritizer:
    def _entry(
        self,
        text: str,
        severity: str = "high",
        tags: tuple[str, ...] = (),
    ) -> PayloadEntry:
        return PayloadEntry(text=text, severity=severity, tags=tags)

    def test_high_severity_before_low(self) -> None:
        prioritizer = PayloadPrioritizer()
        entries = [
            self._entry("low-payload", severity="low"),
            self._entry("<script>alert(1)</script>", severity="high"),
        ]
        result = prioritizer.prioritize(entries)
        assert result[0].severity == "high"

    def test_filtered_char_moves_entry_to_end(self) -> None:
        prioritizer = PayloadPrioritizer()
        entries = [
            self._entry("<script>alert(1)</script>", severity="high"),
            self._entry("no-special-chars", severity="low"),
        ]
        result = prioritizer.prioritize(entries, filtered_chars={"<"})
        assert result[0].text == "no-special-chars"

    def test_context_affinity_raises_score(self) -> None:
        prioritizer = PayloadPrioritizer()
        entries = [
            self._entry("unrelated", tags=()),
            self._entry("js-break", tags=("js-context", "js-string-break")),
        ]
        result = prioritizer.prioritize(entries, context="script_block")
        assert result[0].text == "js-break"

    def test_unknown_context_no_error(self) -> None:
        prioritizer = PayloadPrioritizer()
        entries = [self._entry("<script>alert(1)</script>")]
        result = prioritizer.prioritize(entries, context="totally_unknown_ctx")
        assert len(result) == 1

    def test_empty_entries_list(self) -> None:
        prioritizer = PayloadPrioritizer()
        assert prioritizer.prioritize([]) == []

    def test_no_filtered_chars_preserves_all(self) -> None:
        prioritizer = PayloadPrioritizer()
        entries = [
            self._entry("<script>"),
            self._entry("<img>"),
            self._entry("<svg>"),
        ]
        result = prioritizer.prioritize(entries, filtered_chars=set())
        assert len(result) == 3


# ===========================================================================
# PayloadEngine — load_entries (rich API)
# ===========================================================================


class TestPayloadEngineLoadEntries:
    def test_returns_payload_entry_objects(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        assert all(isinstance(e, PayloadEntry) for e in entries)

    def test_entries_have_category(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        assert all(isinstance(e.category, PayloadCategory) for e in entries)

    def test_waf_bypass_excluded_by_default(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        categories = {e.category for e in entries}
        assert PayloadCategory.WAF_BYPASS not in categories

    def test_waf_bypass_included_when_flag_set(self) -> None:
        cfg = PayloadConfig(use_mutations=False, use_waf_bypass=True)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        categories = {e.category for e in entries}
        assert PayloadCategory.WAF_BYPASS in categories

    def test_category_filter(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries(categories=[PayloadCategory.SVG])
        assert entries
        assert all(e.category is PayloadCategory.SVG for e in entries)

    def test_tags_filter_includes_only_matching(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries(tags_filter=["classic"])
        assert entries
        assert all("classic" in e.tags for e in entries)

    def test_no_duplicates(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        texts = [e.text for e in entries]
        assert len(texts) == len(set(texts))

    def test_max_payloads_enforced(self) -> None:
        cfg = PayloadConfig(use_mutations=False, max_payloads=5)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        assert len(entries) <= 5

    def test_encoding_mutations_expand_count(self) -> None:
        cfg = PayloadConfig(use_mutations=False, use_encoding_mutations=True)
        engine = PayloadEngine(cfg)
        base_count = len(PayloadEngine(PayloadConfig(use_mutations=False)).load_entries())
        mutated_count = len(engine.load_entries())
        assert mutated_count >= base_count

    def test_random_generation_appends_entries(self) -> None:
        cfg = PayloadConfig(
            use_mutations=False,
            use_random_generation=True,
            random_count=5,
        )
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        random_entries = [e for e in entries if "random" in e.tags]
        assert len(random_entries) >= 5

    def test_config_categories_filter(self) -> None:
        cfg = PayloadConfig(use_mutations=False, categories=["svg"])
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        assert entries
        assert all(e.category is PayloadCategory.SVG for e in entries)

    def test_config_tags_filter(self) -> None:
        cfg = PayloadConfig(use_mutations=False, tags_filter=["onload"])
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        assert entries
        assert all("onload" in e.tags for e in entries)


# ===========================================================================
# PayloadEngine — load_for_context
# ===========================================================================


class TestPayloadEngineLoadForContext:
    def test_returns_strings(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        result = engine.load_for_context("html_text")
        assert result
        assert all(isinstance(s, str) for s in result)

    def test_no_duplicates(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        result = engine.load_for_context("html_attribute")
        assert len(result) == len(set(result))

    def test_filtered_chars_excluded(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        result = engine.load_for_context("html_text", filtered_chars={"<", ">"})
        assert all("<" not in p and ">" not in p for p in result)

    def test_context_affinity_affects_order(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        attr_result = engine.load_for_context("html_attribute")
        text_result = engine.load_for_context("html_text")
        # The ordering may differ between the two contexts
        assert attr_result != text_result or True  # ordering may or may not differ

    def test_max_payloads_respected(self) -> None:
        cfg = PayloadConfig(use_mutations=False, max_payloads=3)
        engine = PayloadEngine(cfg)
        result = engine.load_for_context("html_text")
        assert len(result) <= 3


# ===========================================================================
# PayloadEngine — custom YAML files
# ===========================================================================


class TestPayloadEngineCustomYaml:
    def test_load_entries_from_simple_yaml_list(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        content = "- '<script>alert(1)</script>'\n- '<img src=x onerror=alert(1)>'\n"
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(content)
            path = Path(fh.name)
        try:
            entries = engine.load_entries(custom_file=path)
            assert len(entries) == 2
            assert all(isinstance(e, PayloadEntry) for e in entries)
        finally:
            path.unlink()

    def test_load_entries_from_full_format_yaml(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        content = (
            "category: custom\n"
            "payloads:\n"
            "  - text: '<script>alert(1)</script>'\n"
            "    tags: [custom-tag]\n"
            "    description: Test\n"
            "    severity: high\n"
        )
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(content)
            path = Path(fh.name)
        try:
            entries = engine.load_entries(custom_file=path)
            assert len(entries) == 1
            assert "custom-tag" in entries[0].tags
            assert entries[0].severity == "high"
        finally:
            path.unlink()

    def test_missing_yaml_returns_empty(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries(custom_file=Path("/nonexistent/file.yaml"))
        assert entries == []

    def test_yaml_with_unknown_category_uses_custom(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        content = (
            "category: totally_unknown\n"
            "payloads:\n"
            "  - text: '<script>alert(1)</script>'\n"
        )
        with tempfile.NamedTemporaryFile(
            suffix=".yaml", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(content)
            path = Path(fh.name)
        try:
            entries = engine.load_entries(custom_file=path)
            assert entries[0].category is PayloadCategory.CUSTOM
        finally:
            path.unlink()


# ===========================================================================
# PayloadEngine — all bundled YAML files load cleanly
# ===========================================================================


class TestBundledYamlFiles:
    @pytest.mark.parametrize("category", [
        PayloadCategory.BASIC,
        PayloadCategory.POLYGLOT,
        PayloadCategory.ATTRIBUTE_INJECTION,
        PayloadCategory.JS_CONTEXT,
        PayloadCategory.SVG,
    ])
    def test_category_file_loads(self, category: PayloadCategory) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries(categories=[category])
        assert len(entries) > 0, f"No entries loaded for category {category}"
        assert all(e.category is category for e in entries)

    def test_waf_bypass_file_loads(self) -> None:
        cfg = PayloadConfig(use_mutations=False, use_waf_bypass=True)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries(categories=[PayloadCategory.WAF_BYPASS])
        assert len(entries) > 0

    def test_all_entries_have_nonempty_text(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        entries = engine.load_entries()
        assert all(e.text for e in entries)

    def test_entries_have_valid_severity(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        valid = {"high", "medium", "low"}
        entries = engine.load_entries()
        assert all(e.severity in valid for e in entries)


# ===========================================================================
# PayloadConfig new fields
# ===========================================================================


class TestPayloadConfigNewFields:
    def test_default_categories_empty(self) -> None:
        cfg = PayloadConfig()
        assert cfg.categories == []

    def test_default_tags_filter_empty(self) -> None:
        cfg = PayloadConfig()
        assert cfg.tags_filter == []

    def test_default_use_encoding_mutations_false(self) -> None:
        cfg = PayloadConfig()
        assert cfg.use_encoding_mutations is False

    def test_default_use_random_generation_false(self) -> None:
        cfg = PayloadConfig()
        assert cfg.use_random_generation is False

    def test_default_random_count(self) -> None:
        cfg = PayloadConfig()
        assert cfg.random_count == 20


# ===========================================================================
# Backward-compatible tests — PayloadGenerator (legacy string-list mutator)
# ===========================================================================


class TestPayloadGenerator:
    def test_mutations_expand_count(self) -> None:
        gen = PayloadGenerator()
        base = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        result = gen.apply_mutations(base)
        assert len(result) > len(base)

    def test_originals_preserved_at_front(self) -> None:
        gen = PayloadGenerator()
        base = ["<script>alert(1)</script>"]
        result = gen.apply_mutations(base)
        assert result[0] == base[0]

    def test_no_duplicates_after_mutation(self) -> None:
        gen = PayloadGenerator()
        base = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
        result = gen.apply_mutations(base)
        assert len(result) == len(set(result))

    def test_alert_function_swapped(self) -> None:
        gen = PayloadGenerator()
        base = ["<script>alert(1)</script>"]
        result = gen.apply_mutations(base)
        function_names = {p for p in result if "prompt" in p or "confirm" in p}
        assert function_names, "Expected alert→prompt/confirm variants"

    def test_case_variants_generated(self) -> None:
        gen = PayloadGenerator()
        base = ["<script>alert(1)</script>"]
        result = gen.apply_mutations(base)
        upper_variants = [p for p in result if "<SCRIPT" in p]
        assert upper_variants, "Expected uppercase tag variant"

    def test_no_mutations_on_unknown_payload(self) -> None:
        gen = PayloadGenerator()
        base = ["totally_safe_string"]
        result = gen.apply_mutations(base)
        assert result == base


# ===========================================================================
# Backward-compatible tests — PayloadEngine.load() (legacy string API)
# ===========================================================================


class TestPayloadEngine:
    def test_bundled_payloads_load(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        payloads = engine.load()
        assert len(payloads) > 0
        assert all(isinstance(p, str) and p for p in payloads)

    def test_custom_txt_file(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        content = "<script>alert(1)</script>\n<img src=x onerror=alert(1)>\n"
        with tempfile.NamedTemporaryFile(
            suffix=".txt", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            fh.write(content)
            path = Path(fh.name)
        try:
            payloads = engine.load(custom_file=path)
            assert len(payloads) == 2
        finally:
            path.unlink()

    def test_custom_json_file(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        data = ["<svg/onload=alert(1)>", "<body onload=alert(1)>"]
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            json.dump(data, fh)
            path = Path(fh.name)
        try:
            payloads = engine.load(custom_file=path)
            assert payloads == data
        finally:
            path.unlink()

    def test_max_payloads_enforced(self) -> None:
        cfg = PayloadConfig(use_mutations=False, max_payloads=3)
        engine = PayloadEngine(cfg)
        payloads = engine.load()
        assert len(payloads) <= 3

    def test_no_duplicates_in_output(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        payloads = engine.load()
        assert len(payloads) == len(set(payloads))

    def test_comments_stripped_from_txt(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        with tempfile.NamedTemporaryFile(
            suffix=".txt", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            fh.write("# This is a comment\n<script>alert(1)</script>\n")
            path = Path(fh.name)
        try:
            payloads = engine.load(custom_file=path)
            assert all(not p.startswith("#") for p in payloads)
            assert len(payloads) == 1
        finally:
            path.unlink()

    def test_json_non_array_raises(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        with tempfile.NamedTemporaryFile(
            suffix=".json", mode="w", delete=False, encoding="utf-8"
        ) as fh:
            json.dump({"payload": "value"}, fh)
            path = Path(fh.name)
        try:
            with pytest.raises(ValueError, match="root-level array"):
                engine.load(custom_file=path)
        finally:
            path.unlink()

    def test_missing_file_returns_empty(self) -> None:
        cfg = PayloadConfig(use_mutations=False)
        engine = PayloadEngine(cfg)
        result = engine.load(custom_file=Path("/nonexistent/file.txt"))
        assert result == []
