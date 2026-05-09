"""
Payload engine — loads, mutates, prioritizes, and delivers XSS test payloads.

Public surface:
- ``FilterDetector``    — infer which characters a target filters from probe responses
- ``PayloadPrioritizer`` — rank :class:`~payloads.models.PayloadEntry` objects by context fit
- ``PayloadEngine``     — central manager; ``load()`` (backward-compat) and
                          ``load_entries()`` / ``load_for_context()`` (rich API)
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

import yaml

from core.config import PayloadConfig
from payloads.generator import AdvancedPayloadMutator, PayloadGenerator, RandomPayloadGenerator
from payloads.models import PayloadCategory, PayloadEntry

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"

_CATEGORY_FILES: dict[PayloadCategory, str] = {
    PayloadCategory.BASIC: "basic.yaml",
    PayloadCategory.POLYGLOT: "polyglot.yaml",
    PayloadCategory.WAF_BYPASS: "waf_bypass.yaml",
    PayloadCategory.ATTRIBUTE_INJECTION: "attribute_injection.yaml",
    PayloadCategory.JS_CONTEXT: "js_context.yaml",
    PayloadCategory.SVG: "svg.yaml",
}

# Context labels → tags that indicate strong affinity
_CTX_AFFINITY: dict[str, tuple[str, ...]] = {
    "script_block": ("js-context", "js-string-break", "template-literal"),
    "html_attribute": ("attribute-injection", "attribute-breakout", "event-handler"),
    "html_text": ("script-injection", "classic", "polyglot"),
    "html_comment": ("comment-breakout", "polyglot"),
    "url": ("javascript-url", "data-uri"),
    "css_value": ("css-injection",),
}

_SEVERITY_SCORE: dict[str, int] = {"high": 30, "medium": 20, "low": 10}


# ---------------------------------------------------------------------------
# Filter detection
# ---------------------------------------------------------------------------


class FilterDetector:
    """
    Infer which special characters a target application filters by comparing
    probe inputs against their reflected responses.

    Usage::

        detector = FilterDetector()
        # probe_results = {char: response_body_snippet_for_that_char}
        filtered = detector.detect({"<": "response without angle", ">": "> is here"})
        # filtered == {"<"}
    """

    PROBE_CHARS: tuple[str, ...] = (
        "<", ">", '"', "'", "(", ")", ";", "/", "\\", "`", "&",
    )

    def detect(self, probe_results: dict[str, str]) -> set[str]:
        """
        Return the set of characters absent from their corresponding responses.

        Args:
            probe_results: Mapping of ``{probed_char: response_body}`` where the
                           response body is the server reply when that character
                           was injected as a parameter value.

        Returns:
            Set of characters that were not reflected — presumed filtered.
        """
        return {ch for ch, body in probe_results.items() if ch not in body}

    def survivable(self, payloads: list[str], filtered: set[str]) -> list[str]:
        """
        Return the subset of *payloads* that contain none of the *filtered* chars.

        Args:
            payloads: Candidate payload strings.
            filtered: Characters known to be stripped or blocked.

        Returns:
            Payloads that do not rely on any filtered character.
        """
        if not filtered:
            return payloads
        return [p for p in payloads if not any(c in p for c in filtered)]


# ---------------------------------------------------------------------------
# Prioritization
# ---------------------------------------------------------------------------


class PayloadPrioritizer:
    """
    Score and rank :class:`~payloads.models.PayloadEntry` objects by their
    likelihood of success in a given injection context.

    Scoring:
    - Severity:   high=30, medium=20, low=10 base points
    - Affinity:   +10 per tag that matches the context's preferred tag set
    - Filtered:   -1000 if the payload text contains any filtered character
    """

    def prioritize(
        self,
        entries: list[PayloadEntry],
        context: str = "",
        filtered_chars: set[str] | None = None,
    ) -> list[PayloadEntry]:
        """
        Return *entries* sorted by descending relevance score.

        Args:
            entries: Payload entries to rank.
            context: Injection context label (e.g. ``"html_attribute"``).
                     Unknown labels are silently treated as no affinity.
            filtered_chars: Characters the target is known to filter.

        Returns:
            New list sorted best-first.
        """
        fc = filtered_chars or set()
        preferred = set(_CTX_AFFINITY.get(context.lower(), ()))

        def _score(e: PayloadEntry) -> int:
            if fc and any(c in e.text for c in fc):
                return -1000
            base = _SEVERITY_SCORE.get(e.severity.lower(), 10)
            affinity = len(set(e.tags) & preferred) * 10 if preferred else 0
            return base + affinity

        return sorted(entries, key=_score, reverse=True)


# ---------------------------------------------------------------------------
# Payload engine
# ---------------------------------------------------------------------------


class PayloadEngine:
    """
    Central payload manager for the XSS framework.

    Two distinct loading APIs:

    **Legacy / backward-compat**
        :meth:`load` — returns ``list[str]``.  Uses bundled TXT files and the
        legacy :class:`~payloads.generator.PayloadGenerator` for mutations.
        All existing call sites continue to work unchanged.

    **Rich / metadata-aware**
        :meth:`load_entries` — returns ``list[PayloadEntry]`` with full
        category, tag, severity, and source metadata.  Driven by the YAML
        payload files and the advanced mutation/encoding pipeline.

        :meth:`load_for_context` — calls :meth:`load_entries`, runs
        :class:`PayloadPrioritizer`, and returns a plain ``list[str]``
        pre-sorted for the given injection context.

    Args:
        config: :class:`~core.config.PayloadConfig` that controls mutations,
                WAF-bypass inclusion, category/tag filters, and payload cap.
    """

    def __init__(self, config: PayloadConfig) -> None:
        self._config = config
        self._generator = PayloadGenerator()
        self._mutator = AdvancedPayloadMutator()
        self._rng_gen = RandomPayloadGenerator()
        self._prioritizer = PayloadPrioritizer()

    # ------------------------------------------------------------------
    # Rich API
    # ------------------------------------------------------------------

    def load_entries(
        self,
        *,
        custom_file: Optional[Path] = None,
        categories: Optional[list[PayloadCategory]] = None,
        tags_filter: Optional[list[str]] = None,
    ) -> list[PayloadEntry]:
        """
        Build and return the full :class:`~payloads.models.PayloadEntry` list.

        Processing order:
        1. Load from YAML category files (or *custom_file* if given).
        2. Apply :class:`~payloads.generator.AdvancedPayloadMutator` if
           ``use_encoding_mutations`` is enabled.
        3. Append random payloads if ``use_random_generation`` is enabled.
        4. Filter by *tags_filter* / ``config.tags_filter`` if non-empty.
        5. Deduplicate by payload text (first occurrence wins).
        6. Slice to ``max_payloads`` if configured.

        Args:
            custom_file: Optional path to a custom payload file
                         (``.yaml``/``.yml``, ``.json``, or ``.txt``).
                         When provided, bundled YAML files are skipped.
            categories: Explicit list of :class:`~payloads.models.PayloadCategory`
                        values to load.  Overrides ``config.categories``.
            tags_filter: Include only entries whose tags overlap this set.
                         Overrides ``config.tags_filter``.

        Returns:
            Ordered, deduplicated list of :class:`~payloads.models.PayloadEntry`.
        """
        # Resolve category list
        active_cats: Optional[list[PayloadCategory]] = categories
        if active_cats is None and self._config.categories:
            active_cats = []
            for c in self._config.categories:
                try:
                    active_cats.append(PayloadCategory(c))
                except ValueError:
                    logger.warning("Unknown payload category in config: %r", c)

        # Source
        if custom_file:
            entries = self._load_custom_entries(custom_file)
        else:
            entries = self._load_category_files(active_cats)

        # Mutations
        if self._config.use_encoding_mutations:
            entries = self._mutator.apply_mutations(entries)

        # Random generation
        if self._config.use_random_generation:
            entries = entries + self._rng_gen.generate(self._config.random_count)

        # Tag filtering
        active_tags = set(tags_filter or self._config.tags_filter)
        if active_tags:
            entries = [e for e in entries if active_tags.intersection(e.tags)]

        # Deduplicate
        seen: set[str] = set()
        deduped: list[PayloadEntry] = []
        for e in entries:
            if e.text not in seen:
                seen.add(e.text)
                deduped.append(e)

        if self._config.max_payloads is not None:
            deduped = deduped[: self._config.max_payloads]

        logger.info("load_entries: %d payload entries ready", len(deduped))
        return deduped

    def load_for_context(
        self,
        context: str,
        *,
        filtered_chars: Optional[set[str]] = None,
        custom_file: Optional[Path] = None,
    ) -> list[str]:
        """
        Return payload strings pre-sorted for the given injection *context*.

        Calls :meth:`load_entries`, then :class:`PayloadPrioritizer`, then
        strips entries that contain filtered characters.

        Args:
            context: Injection context label (``"html_attribute"``,
                     ``"script_block"``, ``"html_text"``, ``"url"``, …).
            filtered_chars: Characters known to be blocked by the target.
            custom_file: Forwarded to :meth:`load_entries`.

        Returns:
            Ordered list of payload strings, best candidates first.
        """
        entries = self.load_entries(custom_file=custom_file)
        ranked = self._prioritizer.prioritize(entries, context, filtered_chars)
        fc = filtered_chars or set()
        texts = list(dict.fromkeys(
            e.text for e in ranked
            if e.text and not (fc and any(c in e.text for c in fc))
        ))

        if self._config.max_payloads is not None:
            texts = texts[: self._config.max_payloads]

        return texts

    # ------------------------------------------------------------------
    # Legacy / backward-compat API
    # ------------------------------------------------------------------

    def load(self, custom_file: Optional[Path] = None) -> list[str]:
        """
        Build and return the payload list for a scan session.

        This is the original ``load()`` interface; all existing call sites
        work without modification.

        Processing order:
        1. Load base payloads (bundled TXT or *custom_file*).
        2. Apply :class:`~payloads.generator.PayloadGenerator` mutations if enabled.
        3. Append WAF-bypass payloads from bundled TXT if enabled.
        4. Deduplicate, preserving order.
        5. Slice to ``max_payloads`` if configured.

        Args:
            custom_file: Optional path to a ``.txt`` or ``.json`` payload file.

        Returns:
            Ordered, deduplicated list of payload strings.
        """
        if custom_file:
            payloads = self._load_file(custom_file)
            logger.info("Loaded %d payloads from %s", len(payloads), custom_file)
        else:
            payloads = self._load_bundled()

        if self._config.use_mutations:
            payloads = self._generator.apply_mutations(payloads)

        if self._config.use_waf_bypass:
            waf_path = _DATA_DIR / "waf_bypass.txt"
            bypass = self._load_file(waf_path) if waf_path.exists() else []
            payloads = list(dict.fromkeys(payloads + bypass))
            logger.debug("WAF-bypass variants loaded; total: %d", len(payloads))

        if self._config.max_payloads is not None:
            payloads = payloads[: self._config.max_payloads]

        logger.info("Payload engine ready: %d payloads", len(payloads))
        return payloads

    # ------------------------------------------------------------------
    # Internal loaders
    # ------------------------------------------------------------------

    def _load_category_files(
        self,
        categories: Optional[list[PayloadCategory]],
    ) -> list[PayloadEntry]:
        """Load YAML category files, defaulting to all non-WAF categories."""
        if categories is not None:
            cats = categories
        else:
            cats = [
                c
                for c in PayloadCategory
                if c != PayloadCategory.CUSTOM
                and (
                    c != PayloadCategory.WAF_BYPASS
                    or self._config.use_waf_bypass
                )
            ]

        entries: list[PayloadEntry] = []
        for cat in cats:
            fname = _CATEGORY_FILES.get(cat)
            if not fname:
                continue
            path = _DATA_DIR / fname
            entries.extend(self._load_yaml_entries(path))

        return entries

    def _load_custom_entries(self, path: Path) -> list[PayloadEntry]:
        """Load a user-supplied file and wrap contents as CUSTOM entries."""
        if not path.exists():
            logger.error("Custom payload file not found: %s", path)
            return []

        suffix = path.suffix.lower()
        if suffix in (".yaml", ".yml"):
            return self._load_yaml_entries(path)

        texts = self._load_file(path)
        return [
            PayloadEntry(
                text=t,
                category=PayloadCategory.CUSTOM,
                source=path.name,
            )
            for t in texts
        ]

    def _load_yaml_entries(self, path: Path) -> list[PayloadEntry]:
        """
        Parse a YAML payload file into :class:`~payloads.models.PayloadEntry` objects.

        Supports two formats:

        - **Full format** (bundled files): root is a dict with ``category``
          string and ``payloads`` list of objects with ``text`` key.
        - **Simple list**: root is a YAML sequence of plain strings.
        """
        if not path.exists():
            logger.debug("YAML payload file not found, skipping: %s", path)
            return []

        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            logger.error("Failed to parse YAML payload file %s: %s", path, exc)
            return []

        # Simple list of strings
        if isinstance(raw, list):
            return [
                PayloadEntry(
                    text=str(item).strip(),
                    category=PayloadCategory.CUSTOM,
                    source=path.name,
                )
                for item in raw
                if item and str(item).strip()
            ]

        # Full format: {category: ..., payloads: [...]}
        category_str = raw.get("category", "custom")
        try:
            category = PayloadCategory(category_str)
        except ValueError:
            category = PayloadCategory.CUSTOM

        entries: list[PayloadEntry] = []
        for item in raw.get("payloads", []):
            if not item:
                continue
            text = str(item.get("text", "")).strip()
            if not text:
                continue
            tags = tuple(str(t) for t in item.get("tags", []))
            entries.append(
                PayloadEntry(
                    text=text,
                    category=category,
                    tags=tags,
                    description=str(item.get("description", "")),
                    severity=str(item.get("severity", "high")).lower(),
                    source=path.name,
                )
            )

        logger.debug("Loaded %d entries from %s", len(entries), path.name)
        return entries

    def _load_bundled(self) -> list[str]:
        """Load the bundled base payload set from the legacy TXT file."""
        path = _DATA_DIR / "base_payloads.txt"
        payloads = self._load_file(path)
        logger.debug("Loaded %d bundled base payloads", len(payloads))
        return payloads

    @staticmethod
    def _load_file(path: Path) -> list[str]:
        """
        Load payloads from a ``.txt`` or ``.json`` file.

        - ``.txt``: one payload per line; ``#``-prefixed lines are comments.
        - ``.json``: must be a root-level array of strings.

        Args:
            path: Payload file path.

        Returns:
            Deduplicated list of non-empty payload strings.

        Raises:
            ValueError: If a JSON file does not contain a root-level array.
        """
        if not path.exists():
            logger.error("Payload file not found: %s", path)
            return []

        text = path.read_text(encoding="utf-8")

        if path.suffix.lower() == ".json":
            data = json.loads(text)
            if not isinstance(data, list):
                raise ValueError(
                    f"JSON payload file must contain a root-level array: {path}"
                )
            payloads = [str(p) for p in data if p]
        else:
            payloads = [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            ]

        return list(dict.fromkeys(payloads))
