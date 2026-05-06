"""Unit tests for the payload engine and generator."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from core.config import PayloadConfig
from payloads.engine import PayloadEngine
from payloads.generator import PayloadGenerator


# ---------------------------------------------------------------------------
# PayloadGenerator
# ---------------------------------------------------------------------------


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
        """Payloads without recognised patterns should not generate mutations."""
        gen = PayloadGenerator()
        base = ["totally_safe_string"]
        result = gen.apply_mutations(base)
        assert result == base  # nothing to mutate


# ---------------------------------------------------------------------------
# PayloadEngine
# ---------------------------------------------------------------------------


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
