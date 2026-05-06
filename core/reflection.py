"""
Reflection analysis engine.

Determines whether an injected marker appears in an HTTP response and
classifies the reflection context (HTML body, attribute, script block,
style block, comment, or URL).  Context classification drives severity
scoring and is surfaced in reports to guide manual verification.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Optional


class ReflectionContext(Enum):
    """Where in the HTTP response the marker was found."""

    HTML_BODY = auto()
    HTML_ATTRIBUTE = auto()
    SCRIPT_BLOCK = auto()
    STYLE_BLOCK = auto()
    COMMENT = auto()
    UNKNOWN = auto()


@dataclass(frozen=True)
class ReflectionResult:
    """
    Immutable result of a single reflection analysis pass.

    Supports boolean evaluation (``if result:``) so callers can treat it
    like a nullable value without accessing :attr:`reflected` directly.
    """

    reflected: bool
    marker: str
    context: ReflectionContext = ReflectionContext.UNKNOWN
    snippet: Optional[str] = None

    def __bool__(self) -> bool:
        return self.reflected


# ---------------------------------------------------------------------------
# Pre-compiled context detection patterns.
# Each entry is (context, pattern_template) where ``{marker}`` is substituted
# at analysis time with the regex-escaped marker string.
# ---------------------------------------------------------------------------

_CONTEXT_PATTERNS: list[tuple[ReflectionContext, str, int]] = [
    (
        ReflectionContext.SCRIPT_BLOCK,
        r"<script[^>]*>[\s\S]*?{marker}[\s\S]*?</script>",
        re.IGNORECASE | re.DOTALL,
    ),
    (
        ReflectionContext.STYLE_BLOCK,
        r"<style[^>]*>[\s\S]*?{marker}[\s\S]*?</style>",
        re.IGNORECASE | re.DOTALL,
    ),
    (
        ReflectionContext.HTML_ATTRIBUTE,
        r"""[\w:-]+=(?:"[^"]*{marker}[^"]*"|'[^']*{marker}[^']*'|[^\s>]*{marker}[^\s>]*)""",
        re.IGNORECASE,
    ),
    (
        ReflectionContext.COMMENT,
        r"<!--[\s\S]*?{marker}[\s\S]*?-->",
        re.DOTALL,
    ),
]

_SNIPPET_WINDOW = 80  # characters of surrounding context to capture


class ReflectionAnalyzer:
    """
    Stateless analyzer that checks HTTP response text for marker reflection.

    One instance can be shared across all concurrent scan tasks — all methods
    are pure functions with no mutable state.
    """

    def analyze(self, response_text: str, marker: str) -> ReflectionResult:
        """
        Check whether *marker* is reflected in *response_text*.

        Args:
            response_text: Raw text body of the HTTP response.
            marker: The unique string injected alongside the XSS payload.

        Returns:
            A :class:`ReflectionResult`. Falsy when the marker is absent.
        """
        if marker not in response_text:
            return ReflectionResult(reflected=False, marker=marker)

        context = self._classify_context(response_text, marker)
        snippet = self._extract_snippet(response_text, marker)
        return ReflectionResult(
            reflected=True,
            marker=marker,
            context=context,
            snippet=snippet,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _classify_context(self, text: str, marker: str) -> ReflectionContext:
        escaped = re.escape(marker)
        for context, template, flags in _CONTEXT_PATTERNS:
            pattern = re.compile(template.replace("{marker}", escaped), flags)
            if pattern.search(text):
                return context
        return ReflectionContext.HTML_BODY

    def _extract_snippet(self, text: str, marker: str) -> str:
        """Return a short excerpt of *text* centred on the first *marker* hit."""
        idx = text.find(marker)
        start = max(0, idx - _SNIPPET_WINDOW)
        end = min(len(text), idx + len(marker) + _SNIPPET_WINDOW)
        raw = text[start:end].replace("\n", " ").replace("\r", "")
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        return f"{prefix}{raw}{suffix}"
