"""
Advanced reflection analysis engine.

Architecture
------------
The engine is composed of five focused components assembled by the public
:class:`ReflectionAnalyzer` facade:

1. **_EncodingAnalyzer** — inspects the raw HTML source window around the
   marker to determine which dangerous characters (``<``, ``>``, ``"``, etc.)
   were preserved, HTML-entity-encoded, URL-encoded, JS-escaped, or filtered
   entirely.

2. **_ScriptContextClassifier** — runs a minimal JS lexer state-machine to
   decide whether the marker sits in bare executable code, inside a string
   literal, or inside a comment within a ``<script>`` block.

3. **_DomContextDetector** — uses BeautifulSoup to walk the parsed DOM and
   locate every occurrence of the marker, classifying each by its structural
   position (tag text node, attribute type, script, style, comment, etc.).
   Falls back to regex heuristics when the HTML is too malformed to parse.

4. **_FalsePositiveDetector** — applies statistical and structural heuristics
   to rule out reflections that are not genuinely injected (e.g. static content
   that happens to contain the same string, or over-sanitised output).

5. **_ResponseDiffer** — token-level diff between a baseline response and the
   payload response; used to confirm the marker only appears in new content.

All result types are frozen dataclasses so they are safe to share across
concurrent async tasks without copying.
"""

from __future__ import annotations

import difflib
import html as _html_module
import logging
import re
from dataclasses import dataclass, field
from enum import Enum, IntEnum, auto
from typing import Optional

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Public enumerations
# ---------------------------------------------------------------------------


class ConfidenceLevel(IntEnum):
    """
    Exploitability confidence of a single reflection occurrence.

    Ordered so that ``CRITICAL > HIGH > MEDIUM > LOW`` comparisons work
    directly.  Use ``.name`` for string labels in reports.
    """

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ReflectionContext(Enum):
    """
    Structural location of a marker reflection inside an HTTP response.

    Ordered roughly by default exploitability (most dangerous first) though
    actual exploitability also depends on encoding state.
    """

    SCRIPT_BLOCK = auto()
    """Inside ``<script>`` — marker is in bare executable JavaScript code."""

    SCRIPT_STRING = auto()
    """Inside ``<script>`` — marker is inside a JS string or template literal."""

    HTML_ATTRIBUTE_EVENT = auto()
    """Inline event handler attribute (``onclick``, ``onerror``, etc.)."""

    HTML_ATTRIBUTE_URL = auto()
    """URL-bearing attribute (``href``, ``src``, ``action``, ``formaction``, …)."""

    HTML_ATTRIBUTE = auto()
    """Generic HTML attribute value that is not a URL or event handler."""

    HTML_TEXT = auto()
    """Plain text node inside the HTML body."""

    STYLE_BLOCK = auto()
    """Inside a ``<style>`` block."""

    HTML_COMMENT = auto()
    """Inside an HTML comment (``<!-- … -->``)."""

    META_TAG = auto()
    """Inside a ``<meta>`` tag attribute (``content``, ``http-equiv``, …)."""

    UNKNOWN = auto()
    """Context could not be determined (malformed HTML, fallback path)."""


# ---------------------------------------------------------------------------
# Constant tables
# ---------------------------------------------------------------------------

_EVENT_HANDLER_ATTRS: frozenset[str] = frozenset({
    "onabort", "onanimationend", "onanimationiteration", "onanimationstart",
    "onbeforeunload", "onblur", "onchange", "onclick", "onclose",
    "oncontextmenu", "oncopy", "oncut", "ondblclick", "ondrag", "ondragend",
    "ondragenter", "ondragleave", "ondragover", "ondragstart", "ondrop",
    "onerror", "onfocus", "onfocusin", "onfocusout", "onformdata",
    "onhashchange", "oninput", "oninvalid", "onkeydown", "onkeypress",
    "onkeyup", "onload", "onmousedown", "onmouseenter", "onmouseleave",
    "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onpageshow",
    "onpagehide", "onpaste", "onplay", "onpointercancel", "onpointerdown",
    "onpointerenter", "onpointerleave", "onpointermove", "onpointerout",
    "onpointerover", "onpointerup", "onpopstate", "onreadystatechange",
    "onreset", "onresize", "onscroll", "onselect", "onstart", "onstorage",
    "onsubmit", "ontoggle", "ontransitionend", "onunload", "onwheel",
})

_URL_ATTRS: frozenset[str] = frozenset({
    "action", "background", "cite", "codebase", "data", "formaction",
    "href", "longdesc", "manifest", "ping", "poster", "profile", "src",
    "usemap", "xlink:href",
})

# Characters relevant to XSS exploitation, keyed by the context they matter in
_CONTEXT_BREAKOUT_CHARS: dict[ReflectionContext, tuple[str, ...]] = {
    ReflectionContext.SCRIPT_BLOCK:         ("(", ")", ";", "<", ">"),
    ReflectionContext.SCRIPT_STRING:        ('"', "'", "`", "\\"),
    ReflectionContext.HTML_ATTRIBUTE_EVENT: ("(", ")", ";", "`"),
    ReflectionContext.HTML_ATTRIBUTE_URL:   (":", "/", "(", ")"),
    ReflectionContext.HTML_ATTRIBUTE:       ('"', "'", ">", "<"),
    ReflectionContext.HTML_TEXT:            ("<", ">"),
    ReflectionContext.STYLE_BLOCK:          ("(", ")", ":", "/"),
    ReflectionContext.HTML_COMMENT:         ("-", ">"),
    ReflectionContext.META_TAG:             (";", "(", ")"),
    ReflectionContext.UNKNOWN:              ("<", ">", '"', "'"),
}

# All dangerous chars we track across every context
_ALL_DANGEROUS: tuple[str, ...] = ("<", ">", '"', "'", "(", ")", ";", "/", "`", "\\", "=")

# HTML entity representations of dangerous chars (lower-case names only for speed)
_ENTITY_FORMS: dict[str, tuple[str, ...]] = {
    "<":  ("&lt;", "&#60;", "&#x3c;", "&#x3C;"),
    ">":  ("&gt;", "&#62;", "&#x3e;", "&#x3E;"),
    '"':  ("&quot;", "&#34;", "&#x22;"),
    "'":  ("&apos;", "&#39;", "&#x27;"),
    "(":  ("&#40;", "&#x28;"),
    ")":  ("&#41;", "&#x29;"),
    ";":  ("&#59;", "&#x3b;", "&#x3B;"),
    "&":  ("&amp;", "&#38;", "&#x26;"),
}

_URL_ENCODED_FORMS: dict[str, tuple[str, ...]] = {
    "<":  ("%3C", "%3c"),
    ">":  ("%3E", "%3e"),
    '"':  ("%22",),
    "'":  ("%27",),
    "(":  ("%28",),
    ")":  ("%29",),
    ";":  ("%3B", "%3b"),
    "/":  ("%2F", "%2f"),
    ":":  ("%3A", "%3a"),
    "\\": ("%5C", "%5c"),
    "&":  ("%26",),
    "=":  ("%3D", "%3d"),
    "`":  ("%60",),
}

_JS_ESCAPE_FORMS: dict[str, tuple[str, ...]] = {
    "<":  ("\\x3c", "\\x3C", "\\u003c", "\\u003C"),
    ">":  ("\\x3e", "\\x3E", "\\u003e", "\\u003E"),
    '"':  ("\\x22", "\\u0022", '\\"'),
    "'":  ("\\x27", "\\u0027", "\\'"),
    "(":  ("\\x28", "\\u0028"),
    ")":  ("\\x29", "\\u0029"),
    ";":  ("\\x3b", "\\x3B", "\\u003b"),
    "/":  ("\\x2f", "\\x2F", "\\u002f"),
    "`":  ("\\x60", "\\u0060"),
}

_HTML_ENTITY_ANYWHERE_RE = re.compile(r"&(?:#x[0-9a-fA-F]+|#\d+|\w+);", re.IGNORECASE)

# Encoding analysis window: chars on each side of the marker in the raw source
_ENC_WINDOW = 160


# ---------------------------------------------------------------------------
# Data models (all frozen — safe for async sharing)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EncodingFingerprint:
    """
    Encoding state observed in the raw HTML source around the reflected marker.

    Tells the scorer exactly which dangerous characters survived unescaped,
    which were encoded, and which were stripped, enabling context-aware
    exploitability judgements.
    """

    raw_context: str
    """Raw HTML source excerpt (±160 chars) centred on the marker."""

    encoding_types: tuple[str, ...]
    """
    Detected encoding schemes: any of ``"none"``, ``"html_entity"``,
    ``"url_encoded"``, ``"js_escaped"``, ``"double_encoded"``.
    """

    dangerous_chars_preserved: tuple[str, ...]
    """Dangerous chars present in unencoded form inside the raw context."""

    dangerous_chars_encoded: tuple[str, ...]
    """Dangerous chars found only in encoded form (entity / percent / JS escape)."""

    dangerous_chars_filtered: tuple[str, ...]
    """Dangerous chars that appear in the injected payload but are absent here."""

    breakout_possible: bool
    """True when at least one dangerous char is present unencoded."""

    exploitation_difficulty: str
    """``TRIVIAL`` | ``EASY`` | ``MODERATE`` | ``HARD`` | ``NONE``"""


@dataclass(frozen=True)
class ReflectionOccurrence:
    """One confirmed location where the marker was found in the parsed response."""

    context: ReflectionContext
    confidence: ConfidenceLevel
    encoding: EncodingFingerprint
    snippet: str
    char_offset: int
    tag_name: Optional[str]
    attribute_name: Optional[str]
    in_js_string: bool
    js_string_quote: Optional[str]
    exploitation_notes: str


@dataclass(frozen=True)
class ReflectionResult:
    """
    Comprehensive, immutable result of analysing one HTTP response for a marker.

    Backwards-compatible with the original simple result:

    - ``bool(result)`` — True if reflected AND not a false positive
    - ``result.context`` — best context (highest confidence occurrence)
    - ``result.snippet`` — evidence excerpt

    New consumers can additionally access ``confidence``, ``occurrences``,
    ``encoding``, and ``is_false_positive``.
    """

    reflected: bool
    marker: str
    context: ReflectionContext = ReflectionContext.UNKNOWN
    confidence: ConfidenceLevel = ConfidenceLevel.LOW
    snippet: Optional[str] = None
    occurrences: tuple[ReflectionOccurrence, ...] = field(default_factory=tuple)
    encoding: Optional[EncodingFingerprint] = None
    is_false_positive: bool = False

    def __bool__(self) -> bool:
        return self.reflected and not self.is_false_positive

    @property
    def severity(self) -> str:
        """Confidence label as a severity string (``HIGH``, ``CRITICAL``, …)."""
        return self.confidence.name


# ---------------------------------------------------------------------------
# Component 1 — Encoding analyser
# ---------------------------------------------------------------------------


class _EncodingAnalyzer:
    """
    Inspects the raw HTML source window around the marker to fingerprint
    the encoding transformations applied by the server.
    """

    def analyze(
        self,
        raw_response: str,
        marker: str,
        payload: Optional[str],
        context: ReflectionContext = ReflectionContext.UNKNOWN,
    ) -> EncodingFingerprint:
        """
        Args:
            raw_response: Full raw HTTP response body.
            marker:       The alphabetic detection string that was injected.
            payload:      The complete marked payload (``<script>alert(M)</script>``).
                          When provided, only chars that appear in the payload are
                          checked; otherwise all :attr:`_ALL_DANGEROUS` are checked.
            context:      The already-classified context (used to select the most
                          relevant dangerous chars to examine).

        Returns:
            An :class:`EncodingFingerprint`.
        """
        idx = raw_response.find(marker)
        if idx == -1:
            return self._null_fingerprint()

        start = max(0, idx - _ENC_WINDOW)
        end = min(len(raw_response), idx + len(marker) + _ENC_WINDOW)
        raw_ctx = raw_response[start:end]

        check_raw = raw_ctx

        # Select chars to check: from the payload if known, else generic set
        if payload:
            chars_to_check = [c for c in _ALL_DANGEROUS if c in payload]
        else:
            chars_to_check = list(_CONTEXT_BREAKOUT_CHARS.get(context, _ALL_DANGEROUS))

        preserved: list[str] = []
        encoded: list[str] = []
        filtered: list[str] = []
        enc_types: set[str] = set()

        for ch in chars_to_check:
            # Check encoded forms FIRST — a char may be entity-encoded in the
            # payload reflection even when a structural tag elsewhere in the
            # window has the same raw character (e.g. <p> contains literal <).
            found_encoded = False
            for form in _ENTITY_FORMS.get(ch, ()):
                if form.lower() in check_raw.lower():
                    enc_types.add("html_entity")
                    found_encoded = True
                    break
            if not found_encoded:
                for form in _URL_ENCODED_FORMS.get(ch, ()):
                    if form.lower() in check_raw.lower():
                        enc_types.add("url_encoded")
                        found_encoded = True
                        break
            if not found_encoded:
                for form in _JS_ESCAPE_FORMS.get(ch, ()):
                    if form.lower() in check_raw.lower():
                        enc_types.add("js_escaped")
                        found_encoded = True
                        break

            if found_encoded:
                encoded.append(ch)
            elif ch in check_raw:
                preserved.append(ch)
            elif payload and ch in payload:
                # Char was in the payload but is completely absent → filtered
                filtered.append(ch)

        # Detect double-encoding: if the HTML-decoded check context still contains entities
        try:
            decoded_once = _html_module.unescape(check_raw)
            if _HTML_ENTITY_ANYWHERE_RE.search(decoded_once):
                enc_types.add("double_encoded")
        except Exception:
            pass

        if not enc_types:
            enc_types.add("none")

        breakout = bool(preserved)

        # Exploitation difficulty based on how many critical chars survived
        num_preserved = len(preserved)
        if not preserved:
            difficulty = "NONE" if filtered else "HARD"
        elif num_preserved >= 3:
            difficulty = "TRIVIAL"
        elif num_preserved == 2:
            difficulty = "EASY"
        else:
            difficulty = "MODERATE"

        return EncodingFingerprint(
            raw_context=raw_ctx,
            encoding_types=tuple(sorted(enc_types)),
            dangerous_chars_preserved=tuple(preserved),
            dangerous_chars_encoded=tuple(encoded),
            dangerous_chars_filtered=tuple(filtered),
            breakout_possible=breakout,
            exploitation_difficulty=difficulty,
        )

    @staticmethod
    def _null_fingerprint() -> EncodingFingerprint:
        return EncodingFingerprint(
            raw_context="",
            encoding_types=("none",),
            dangerous_chars_preserved=(),
            dangerous_chars_encoded=(),
            dangerous_chars_filtered=(),
            breakout_possible=False,
            exploitation_difficulty="NONE",
        )


# ---------------------------------------------------------------------------
# Component 2 — JavaScript string context classifier
# ---------------------------------------------------------------------------


class _ScriptContextClassifier:
    """
    Minimal JS lexer state-machine to determine whether the marker sits in
    bare executable code, inside a string/template literal, or inside a
    JS comment.

    Handles: ``"`` / ``'`` / `````  string literals, ``\\`` escape sequences,
    ``//`` line comments, and ``/* */`` block comments.  Does NOT parse
    regex literals (distinguishing them from division is context-sensitive);
    those rare cases fall through as bare-code, which is the safer/higher-
    confidence assumption.
    """

    def classify(
        self, script_text: str, marker: str
    ) -> tuple[ReflectionContext, Optional[str]]:
        """
        Args:
            script_text: Raw text content of a ``<script>`` element.
            marker:      The detection string to locate.

        Returns:
            ``(context, quote_char)`` where *context* is either
            :attr:`ReflectionContext.SCRIPT_BLOCK` (bare code) or
            :attr:`ReflectionContext.SCRIPT_STRING` (string literal).
            *quote_char* is the enclosing delimiter when in a string, else ``None``.
        """
        idx = script_text.find(marker)
        if idx == -1:
            return ReflectionContext.SCRIPT_BLOCK, None

        in_str, quote = self._walk(script_text, idx)
        if in_str:
            return ReflectionContext.SCRIPT_STRING, quote
        return ReflectionContext.SCRIPT_BLOCK, None

    @staticmethod
    def _walk(src: str, stop: int) -> tuple[bool, Optional[str]]:
        """Walk *src* up to *stop*, tracking JS lexical string state."""
        i = 0
        n = len(src)
        in_string = False
        quote_char: Optional[str] = None

        while i < stop and i < n:
            c = src[i]

            if not in_string:
                if c in ('"', "'", "`"):
                    in_string = True
                    quote_char = c
                elif c == "/" and i + 1 < n:
                    nxt = src[i + 1]
                    if nxt == "/":                         # line comment
                        while i < stop and i < n and src[i] != "\n":
                            i += 1
                        continue
                    elif nxt == "*":                       # block comment
                        i += 2
                        while i + 1 < n and i < stop:
                            if src[i] == "*" and src[i + 1] == "/":
                                i += 2
                                break
                            i += 1
                        continue
            else:
                if c == "\\" and i + 1 < n:
                    i += 2                                 # skip escaped char
                    continue
                if c == quote_char:
                    in_string = False
                    quote_char = None

            i += 1

        return in_string, quote_char


# ---------------------------------------------------------------------------
# Component 3 — DOM context detector
# ---------------------------------------------------------------------------


class _DomContextDetector:
    """
    Uses BeautifulSoup to walk the parsed DOM and produce a list of
    :class:`ReflectionOccurrence` objects, one per structural location where
    the marker appears.
    """

    _SNIPPET_WINDOW = 100

    def __init__(self) -> None:
        self._js_classifier = _ScriptContextClassifier()

    def find_occurrences(
        self,
        raw_response: str,
        marker: str,
        payload: Optional[str],
        enc_analyzer: _EncodingAnalyzer,
    ) -> list[ReflectionOccurrence]:
        """
        Parse *raw_response* and return every structural location of *marker*.

        Falls back to regex when BeautifulSoup raises a parse exception.
        Results are sorted by confidence (highest first).
        """
        try:
            soup = BeautifulSoup(raw_response, "html.parser")
        except Exception as exc:
            logger.debug("HTML parse error (%s) — using regex fallback", exc)
            return self._regex_fallback(raw_response, marker, payload, enc_analyzer)

        occurrences: list[ReflectionOccurrence] = []

        # Pass 1: text nodes (covers <script>, <style>, comments, plain text)
        for node in soup.find_all(string=True):
            node_str = str(node)
            if marker not in node_str:
                continue
            occ = self._classify_text_node(
                node, node_str, marker, raw_response, payload, enc_analyzer
            )
            if occ:
                occurrences.append(occ)

        # Pass 2: element attributes (event handlers, URL attrs, generic attrs)
        for tag in soup.find_all(True):
            if not isinstance(tag, Tag):
                continue
            for attr_name, attr_val in tag.attrs.items():
                val_str = (
                    " ".join(attr_val) if isinstance(attr_val, list) else str(attr_val)
                )
                if marker not in val_str:
                    continue
                occ = self._classify_attribute(
                    tag, attr_name, val_str, marker, raw_response, payload, enc_analyzer
                )
                if occ:
                    occurrences.append(occ)

        # Deduplicate by (context, char_offset) — the same offset may appear via
        # both passes if BS4 exposes the attribute in both the tag and a text view
        seen: set[tuple[int, ReflectionContext]] = set()
        unique: list[ReflectionOccurrence] = []
        for occ in occurrences:
            key = (occ.char_offset, occ.context)
            if key not in seen:
                seen.add(key)
                unique.append(occ)

        unique.sort(key=lambda o: o.confidence, reverse=True)
        return unique

    # ------------------------------------------------------------------
    # Text-node classification
    # ------------------------------------------------------------------

    def _classify_text_node(
        self,
        node: NavigableString,
        node_str: str,
        marker: str,
        raw: str,
        payload: Optional[str],
        enc: _EncodingAnalyzer,
    ) -> Optional[ReflectionOccurrence]:
        char_offset = raw.find(marker)
        snippet = self._snippet(raw, marker)
        parent = node.parent
        parent_name: str = (
            parent.name.lower()
            if parent and isinstance(parent, Tag) and parent.name
            else ""
        )

        if isinstance(node, Comment):
            encoding = enc.analyze(raw, marker, payload, ReflectionContext.HTML_COMMENT)
            confidence = ConfidenceLevel.LOW
            notes = (
                "Marker reflected inside an HTML comment. "
                "Needs '-->' sequence to break out; check if '-->' is filtered."
            )
            return self._build(
                ReflectionContext.HTML_COMMENT, confidence, encoding,
                snippet, char_offset, parent_name, None, False, None, notes,
            )

        if parent_name == "script":
            encoding = enc.analyze(raw, marker, payload, ReflectionContext.SCRIPT_BLOCK)
            js_ctx, quote = self._js_classifier.classify(node_str, marker)
            if js_ctx == ReflectionContext.SCRIPT_STRING:
                confidence = self._score_script_string(encoding, quote)
                notes = (
                    f"Marker in JS string literal (delimiter: {quote!r}). "
                    f"Need {quote!r} to break out. "
                    f"Exploitation difficulty: {encoding.exploitation_difficulty}."
                )
            else:
                # Bare code — most dangerous script context
                confidence = self._score_bare_script(encoding)
                notes = (
                    "Marker in bare JavaScript execution context. "
                    f"Difficulty: {encoding.exploitation_difficulty}."
                )
            return self._build(
                js_ctx, confidence, encoding,
                snippet, char_offset, "script", None,
                js_ctx == ReflectionContext.SCRIPT_STRING, quote, notes,
            )

        if parent_name == "style":
            encoding = enc.analyze(raw, marker, payload, ReflectionContext.STYLE_BLOCK)
            confidence = (
                ConfidenceLevel.MEDIUM if encoding.breakout_possible else ConfidenceLevel.LOW
            )
            notes = (
                "Marker in CSS block. Exploitation typically requires "
                "expression() (legacy IE) or mXSS via CSS parsing quirks."
            )
            return self._build(
                ReflectionContext.STYLE_BLOCK, confidence, encoding,
                snippet, char_offset, "style", None, False, None, notes,
            )

        # Plain HTML text node
        encoding = enc.analyze(raw, marker, payload, ReflectionContext.HTML_TEXT)
        confidence = self._score_html_text(encoding)
        lt_ok = "<" in encoding.dangerous_chars_preserved
        gt_ok = ">" in encoding.dangerous_chars_preserved
        notes = (
            "Marker in HTML text node. "
            + (
                "Both < and > are unencoded — tag injection is likely possible."
                if lt_ok and gt_ok
                else "< preserved but > encoded — partial injection possible."
                if lt_ok
                else "Key characters (< >) are encoded — tag injection blocked."
            )
        )
        return self._build(
            ReflectionContext.HTML_TEXT, confidence, encoding,
            snippet, char_offset, parent_name or None, None, False, None, notes,
        )

    # ------------------------------------------------------------------
    # Attribute classification
    # ------------------------------------------------------------------

    def _classify_attribute(
        self,
        tag: Tag,
        attr_name: str,
        attr_value: str,
        marker: str,
        raw: str,
        payload: Optional[str],
        enc: _EncodingAnalyzer,
    ) -> Optional[ReflectionOccurrence]:
        char_offset = raw.find(marker)
        snippet = self._snippet(raw, marker)
        attr_lower = attr_name.lower()

        # ── Inline event handler ──────────────────────────────────────────
        if attr_lower in _EVENT_HANDLER_ATTRS:
            encoding = enc.analyze(raw, marker, payload, ReflectionContext.HTML_ATTRIBUTE_EVENT)
            confidence = self._score_event_handler(encoding)
            notes = (
                f"Marker in '{attr_name}' event handler on <{tag.name}>. "
                "This is a JavaScript execution context. "
                + (
                    "( and ) unencoded — function calls possible."
                    if "(" in encoding.dangerous_chars_preserved
                    else "( or ) may be encoded — call syntax may need encoding bypass."
                )
            )
            return self._build(
                ReflectionContext.HTML_ATTRIBUTE_EVENT, confidence, encoding,
                snippet, char_offset, tag.name, attr_name, False, None, notes,
            )

        # ── URL-bearing attribute ─────────────────────────────────────────
        if attr_lower in _URL_ATTRS:
            encoding = enc.analyze(raw, marker, payload, ReflectionContext.HTML_ATTRIBUTE_URL)
            confidence = self._score_url_attr(attr_value, encoding)
            url_lower = attr_value.lower()
            proto_hint = ""
            if "javascript:" in url_lower:
                proto_hint = "javascript: URI detected — direct execution likely."
            elif "data:text/html" in url_lower:
                proto_hint = "data:text/html URI detected — HTML injection in iframe."
            notes = (
                f"Marker in '{attr_name}' URL attribute on <{tag.name}>. "
                + (proto_hint or "Check for javascript:/data: protocol injection.")
            )
            return self._build(
                ReflectionContext.HTML_ATTRIBUTE_URL, confidence, encoding,
                snippet, char_offset, tag.name, attr_name, False, None, notes,
            )

        # ── <meta> tag ────────────────────────────────────────────────────
        if tag.name == "meta":
            encoding = enc.analyze(raw, marker, payload, ReflectionContext.META_TAG)
            confidence = ConfidenceLevel.LOW
            notes = (
                f"Marker in <meta {attr_name}> attribute. "
                "Limited exploitability; check for http-equiv=refresh javascript: URI."
            )
            return self._build(
                ReflectionContext.META_TAG, confidence, encoding,
                snippet, char_offset, "meta", attr_name, False, None, notes,
            )

        # ── Generic attribute ─────────────────────────────────────────────
        encoding = enc.analyze(raw, marker, payload, ReflectionContext.HTML_ATTRIBUTE)
        confidence = self._score_generic_attr(encoding)
        quote_chars = {c for c in ('"', "'", "`") if c in encoding.dangerous_chars_preserved}
        notes = (
            f"Marker in '{attr_name}' attribute on <{tag.name}>. "
            + (
                f"Quote chars {quote_chars} unencoded — attribute breakout possible."
                if quote_chars
                else "Quote chars encoded — attribute breakout may be blocked."
            )
        )
        return self._build(
            ReflectionContext.HTML_ATTRIBUTE, confidence, encoding,
            snippet, char_offset, tag.name, attr_name, False, None, notes,
        )

    # ------------------------------------------------------------------
    # Context-specific confidence scorers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_bare_script(enc: EncodingFingerprint) -> ConfidenceLevel:
        """Bare JS code: already in execution context, encoding matters less."""
        d = enc.exploitation_difficulty
        if d in ("TRIVIAL", "EASY"):
            return ConfidenceLevel.CRITICAL
        if d == "MODERATE":
            return ConfidenceLevel.HIGH
        if d == "HARD":
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @staticmethod
    def _score_script_string(
        enc: EncodingFingerprint, quote: Optional[str]
    ) -> ConfidenceLevel:
        """In a JS string: need the enclosing quote char to break out."""
        if quote and quote in enc.dangerous_chars_preserved:
            return ConfidenceLevel.HIGH
        if enc.exploitation_difficulty in ("TRIVIAL", "EASY"):
            return ConfidenceLevel.HIGH
        if enc.exploitation_difficulty == "MODERATE":
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @staticmethod
    def _score_event_handler(enc: EncodingFingerprint) -> ConfidenceLevel:
        """Event handlers are JS execution contexts; ( and ) are key."""
        exec_chars = {"(", ")", ";"}
        if exec_chars & set(enc.dangerous_chars_preserved):
            return ConfidenceLevel.CRITICAL
        if enc.breakout_possible:
            return ConfidenceLevel.HIGH
        return ConfidenceLevel.MEDIUM

    @staticmethod
    def _score_url_attr(value: str, enc: EncodingFingerprint) -> ConfidenceLevel:
        """URL attributes: javascript:/data: URIs are critical."""
        val_lower = value.lower()
        if "javascript:" in val_lower or "data:text/html" in val_lower:
            return ConfidenceLevel.CRITICAL
        if enc.breakout_possible:
            return ConfidenceLevel.HIGH
        return ConfidenceLevel.MEDIUM

    @staticmethod
    def _score_html_text(enc: EncodingFingerprint) -> ConfidenceLevel:
        """HTML text: need < and > for tag injection."""
        preserved = set(enc.dangerous_chars_preserved)
        if "<" in preserved and ">" in preserved:
            return ConfidenceLevel.HIGH
        if "<" in preserved or ">" in preserved:
            return ConfidenceLevel.MEDIUM
        return ConfidenceLevel.LOW

    @staticmethod
    def _score_generic_attr(enc: EncodingFingerprint) -> ConfidenceLevel:
        """Generic attribute: need a quote char to break out of the value."""
        quote_chars = {'"', "'", "`"}
        if quote_chars & set(enc.dangerous_chars_preserved):
            return (
                ConfidenceLevel.HIGH
                if ">" in enc.dangerous_chars_preserved
                else ConfidenceLevel.MEDIUM
            )
        return ConfidenceLevel.LOW

    # ------------------------------------------------------------------
    # Regex fallback for malformed HTML
    # ------------------------------------------------------------------

    def _regex_fallback(
        self,
        raw: str,
        marker: str,
        payload: Optional[str],
        enc: _EncodingAnalyzer,
    ) -> list[ReflectionOccurrence]:
        """Conservative regex-based detection when BS4 cannot parse the HTML."""
        _FALLBACK: list[tuple[re.Pattern, ReflectionContext]] = [
            (re.compile(r"<script[^>]*>[\s\S]*?" + re.escape(marker), re.IGNORECASE),
             ReflectionContext.SCRIPT_BLOCK),
            (re.compile(r"on\w+\s*=\s*['\"]?[^'\"<>]*?" + re.escape(marker), re.IGNORECASE),
             ReflectionContext.HTML_ATTRIBUTE_EVENT),
            (re.compile(r'(?:href|src|action|formaction)\s*=\s*[\'"]?[^\'"><]*?' + re.escape(marker), re.IGNORECASE),
             ReflectionContext.HTML_ATTRIBUTE_URL),
            (re.compile(r"<!--[\s\S]*?" + re.escape(marker), re.DOTALL),
             ReflectionContext.HTML_COMMENT),
            (re.compile(r"<style[^>]*>[\s\S]*?" + re.escape(marker), re.IGNORECASE),
             ReflectionContext.STYLE_BLOCK),
        ]

        snippet = self._snippet(raw, marker)
        char_offset = raw.find(marker)

        for pattern, ctx in _FALLBACK:
            if pattern.search(raw):
                encoding = enc.analyze(raw, marker, payload, ctx)
                return [self._build(
                    ctx, ConfidenceLevel.MEDIUM, encoding,
                    snippet, char_offset, None, None, False, None,
                    "Classified via regex fallback (HTML parsing failed).",
                )]

        # Default: unknown context in plain body
        encoding = enc.analyze(raw, marker, payload, ReflectionContext.UNKNOWN)
        return [self._build(
            ReflectionContext.UNKNOWN, ConfidenceLevel.LOW, encoding,
            snippet, char_offset, None, None, False, None,
            "Marker found in response; structural context could not be determined.",
        )]

    # ------------------------------------------------------------------
    # Factory helper
    # ------------------------------------------------------------------

    @staticmethod
    def _build(
        context: ReflectionContext,
        confidence: ConfidenceLevel,
        encoding: EncodingFingerprint,
        snippet: str,
        char_offset: int,
        tag_name: Optional[str],
        attribute_name: Optional[str],
        in_js_string: bool,
        js_string_quote: Optional[str],
        exploitation_notes: str,
    ) -> ReflectionOccurrence:
        return ReflectionOccurrence(
            context=context,
            confidence=confidence,
            encoding=encoding,
            snippet=snippet,
            char_offset=char_offset,
            tag_name=tag_name,
            attribute_name=attribute_name,
            in_js_string=in_js_string,
            js_string_quote=js_string_quote,
            exploitation_notes=exploitation_notes,
        )

    @classmethod
    def _snippet(cls, raw: str, marker: str) -> str:
        idx = raw.find(marker)
        w = cls._SNIPPET_WINDOW
        start = max(0, idx - w)
        end = min(len(raw), idx + len(marker) + w)
        text = raw[start:end].replace("\n", " ").replace("\r", "")
        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(raw) else ""
        return f"{prefix}{text}{suffix}"


# ---------------------------------------------------------------------------
# Component 4 — False positive detector
# ---------------------------------------------------------------------------


class _FalsePositiveDetector:
    """
    Applies statistical and structural heuristics to filter out reflections
    that are not genuine injections.
    """

    # Marker repeated this many times suggests static/echoed content
    _MAX_OCCURRENCES = 5

    def check(
        self,
        raw_response: str,
        marker: str,
        occurrences: list[ReflectionOccurrence],
        baseline_text: Optional[str],
    ) -> bool:
        """
        Return ``True`` if the reflection is likely a false positive.

        Checks applied (any match → false positive):

        1. Marker appears more than :attr:`_MAX_OCCURRENCES` times — likely static
           content or a very long reflected string that was pre-existing.
        2. Marker appears in the baseline response (the page returned it even
           without injection).
        3. All occurrences are in comments with no breakout chars — technically
           still a reflection but we don't suppress these; kept for documentation.
        """
        count = raw_response.count(marker)
        if count > self._MAX_OCCURRENCES:
            logger.debug(
                "FP heuristic: marker count %d exceeds threshold %d",
                count, self._MAX_OCCURRENCES,
            )
            return True

        if baseline_text is not None and marker in baseline_text:
            logger.debug("FP heuristic: marker present in baseline response")
            return True

        return False


# ---------------------------------------------------------------------------
# Component 5 — Response differ
# ---------------------------------------------------------------------------


class _ResponseDiffer:
    """Line-level diff utility for baseline-comparison false-positive reduction."""

    def new_lines(self, baseline: str, response: str) -> list[str]:
        """Return lines present in *response* that are absent from *baseline*."""
        sm = difflib.SequenceMatcher(
            None, baseline.splitlines(), response.splitlines(), autojunk=False
        )
        new: list[str] = []
        for tag, _i1, _i2, j1, j2 in sm.get_opcodes():
            if tag in ("insert", "replace"):
                new.extend(response.splitlines()[j1:j2])
        return new

    def marker_confined_to_new_content(
        self, baseline: str, response: str, marker: str
    ) -> bool:
        """
        Return ``True`` if *marker* only appears in lines that are new to
        *response* (i.e. not present in *baseline*).

        A ``False`` result means the marker was already in the baseline, which
        strongly suggests a false positive.
        """
        if marker not in response:
            return False
        if marker in baseline:
            return False  # pre-existing → not injected
        new = self.new_lines(baseline, response)
        return any(marker in line for line in new)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


class ReflectionAnalyzer:
    """
    Advanced, parsing-driven reflection analysis engine.

    Backwards-compatible with the original simple analyser — the same
    :meth:`analyze` signature and ``ReflectionResult.__bool__`` contract are
    maintained.  Richer consumers can access ``confidence``, ``occurrences``,
    ``encoding``, and ``is_false_positive``.

    Thread-safe: no mutable state.  A single instance can be shared across
    all concurrent async scan tasks.

    Basic usage::

        analyzer = ReflectionAnalyzer()

        # Simple (old interface)
        result = analyzer.analyze(response_text, marker)
        if result:
            print(result.context.name, result.snippet)

        # Rich (new interface)
        result = analyzer.analyze(response_text, marker, payload=marked_payload)
        if result:
            print(result.confidence.name, result.encoding.exploitation_difficulty)
            for occ in result.occurrences:
                print(occ.context.name, occ.exploitation_notes)

        # With baseline diff for FP suppression
        result = analyzer.analyze(
            response_text, marker,
            payload=marked_payload,
            baseline_text=baseline_response,
        )
    """

    def __init__(self) -> None:
        self._enc = _EncodingAnalyzer()
        self._dom = _DomContextDetector()
        self._fp = _FalsePositiveDetector()
        self._diff = _ResponseDiffer()

    def analyze(
        self,
        response_text: str,
        marker: str,
        payload: Optional[str] = None,
        baseline_text: Optional[str] = None,
    ) -> ReflectionResult:
        """
        Analyse *response_text* for reflected *marker*.

        Args:
            response_text:  Raw HTTP response body.
            marker:         The unique alphabetic detection string embedded in
                            the injected payload.
            payload:        The full marked payload string (e.g.
                            ``"<script>alert(AbCdEfGh)</script>"``).  Optional,
                            but significantly improves encoding analysis accuracy.
            baseline_text:  A baseline HTTP response from the same URL fetched
                            *without* any payload.  When provided, enables diff-
                            based false positive suppression.

        Returns:
            A :class:`ReflectionResult`.  ``bool(result)`` is ``False`` when the
            marker is absent or the reflection is classified as a false positive.
        """
        if marker not in response_text:
            return ReflectionResult(reflected=False, marker=marker)

        # DOM-based occurrence detection
        occurrences = self._dom.find_occurrences(
            response_text, marker, payload, self._enc
        )

        if not occurrences:
            # Marker is in raw text but BS4 could not map it to any DOM node
            enc = self._enc.analyze(response_text, marker, payload)
            fallback = ReflectionOccurrence(
                context=ReflectionContext.UNKNOWN,
                confidence=ConfidenceLevel.LOW,
                encoding=enc,
                snippet=_DomContextDetector._snippet(response_text, marker),
                char_offset=response_text.find(marker),
                tag_name=None,
                attribute_name=None,
                in_js_string=False,
                js_string_quote=None,
                exploitation_notes=(
                    "Marker present in raw response body but could not be "
                    "mapped to a DOM node — possible in heavily malformed HTML."
                ),
            )
            occurrences = [fallback]

        # False-positive checks
        is_fp = self._fp.check(response_text, marker, occurrences, baseline_text)

        # Diff-based FP suppression (only when baseline is provided)
        if not is_fp and baseline_text is not None:
            if not self._diff.marker_confined_to_new_content(
                baseline_text, response_text, marker
            ):
                is_fp = True
                logger.debug("Diff check: marker not confined to new response content")

        best = occurrences[0]  # sorted by confidence descending

        return ReflectionResult(
            reflected=True,
            marker=marker,
            context=best.context,
            confidence=best.confidence,
            snippet=best.snippet,
            occurrences=tuple(occurrences),
            encoding=best.encoding,
            is_false_positive=is_fp,
        )

    def diff_responses(self, baseline: str, response: str) -> list[str]:
        """
        Return lines present in *response* that are absent from *baseline*.

        Public utility for callers that want direct access to the response
        differ without running a full reflection analysis.
        """
        return self._diff.new_lines(baseline, response)
