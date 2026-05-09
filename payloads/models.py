"""
Payload data models for the XSS framework.

All payload objects are frozen dataclasses — they can be safely shared
across async workers without copying or locking.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class PayloadCategory(str, Enum):
    """Top-level classification of an XSS payload."""

    BASIC = "basic"
    POLYGLOT = "polyglot"
    WAF_BYPASS = "waf_bypass"
    ATTRIBUTE_INJECTION = "attribute_injection"
    JS_CONTEXT = "js_context"
    SVG = "svg"
    CUSTOM = "custom"


@dataclass(frozen=True)
class PayloadEntry:
    """
    Immutable record representing a single XSS payload and its metadata.

    Frozen so instances are safe to share across asyncio tasks without copying.
    """

    text: str
    """The raw XSS payload string."""

    category: PayloadCategory = PayloadCategory.BASIC
    """Semantic category used for filtering and prioritization."""

    tags: tuple[str, ...] = ()
    """Fine-grained labels, e.g. ``("script-injection", "classic")``."""

    description: str = ""
    """Human-readable summary of what this payload tests."""

    severity: str = "high"
    """Relative impact level: ``high``, ``medium``, or ``low``."""

    source: str = ""
    """Origin file or mechanism that produced this entry."""

    def mutated(self, new_text: str, *, note: str = "mutated") -> "PayloadEntry":
        """Return a copy with *new_text*, appending *note* to :attr:`tags`."""
        return PayloadEntry(
            text=new_text,
            category=self.category,
            tags=self.tags + (note,),
            description=self.description,
            severity=self.severity,
            source=self.source,
        )
