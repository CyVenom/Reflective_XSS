"""
Payload mutation and generation logic.

Rather than storing thousands of near-identical payloads on disk, the generator
applies systematic mutations to a compact base set.  This keeps the payload
files readable and auditable while still producing broad coverage.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Mutation tables
# ---------------------------------------------------------------------------

# Alternative JavaScript function names that produce observable side-effects
_ALERT_ALTERNATIVES: list[str] = ["prompt", "confirm", "console.log"]

# Arguments that exfiltrate sensitive data (useful for manual PoC escalation)
_ARG_ALTERNATIVES: list[str] = [
    "document.cookie",
    "document.domain",
    "window.location.href",
]

# Tag name case variants — defeats naive case-sensitive WAF rules
_TAG_CASE_MAPS: list[tuple[str, str]] = [
    ("<script", "<SCRIPT"),
    ("</script", "</SCRIPT"),
    ("<img", "<IMG"),
    ("<svg", "<SVG"),
    ("<body", "<BODY"),
    ("<iframe", "<IFRAME"),
]


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class PayloadGenerator:
    """
    Applies mutation passes to a list of base XSS payloads.

    Mutations expand coverage without duplicating payloads or bloating the
    base payload files with redundant variants.
    """

    def apply_mutations(self, base_payloads: list[str]) -> list[str]:
        """
        Return *base_payloads* extended with auto-generated mutations.

        The original payloads always appear first in the returned list so that
        the most reliable variants are tested before mutated ones.

        Args:
            base_payloads: Deduplicated list of base XSS payloads.

        Returns:
            Combined list of originals + unique mutations.
        """
        mutations: list[str] = []
        for payload in base_payloads:
            mutations.extend(self._mutate(payload))

        combined = list(dict.fromkeys(base_payloads + mutations))
        logger.debug(
            "Mutation pass: %d base payloads → %d total", len(base_payloads), len(combined)
        )
        return combined

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _mutate(self, payload: str) -> list[str]:
        """Generate all applicable variants of a single *payload*."""
        variants: list[str] = []

        variants.extend(self._alternate_functions(payload))
        variants.extend(self._alternate_arguments(payload))
        variants.extend(self._case_variants(payload))

        # Remove variants that are identical to the original
        return [v for v in variants if v != payload]

    def _alternate_functions(self, payload: str) -> list[str]:
        """Swap ``alert`` for semantically equivalent JavaScript functions."""
        if "alert" not in payload:
            return []
        return [payload.replace("alert", alt, 1) for alt in _ALERT_ALTERNATIVES]

    def _alternate_arguments(self, payload: str) -> list[str]:
        """Replace the numeric argument with sensitive property accessors."""
        if "alert(1)" not in payload:
            return []
        return [
            payload.replace("alert(1)", f"alert({arg})", 1)
            for arg in _ARG_ALTERNATIVES
        ]

    def _case_variants(self, payload: str) -> list[str]:
        """Apply tag-name uppercasing to defeat case-sensitive WAF matching."""
        variants: list[str] = []
        for lower, upper in _TAG_CASE_MAPS:
            if lower in payload:
                variants.append(payload.replace(lower, upper))
        return variants
