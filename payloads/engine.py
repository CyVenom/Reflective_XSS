"""
Payload engine — loads, mutates, and delivers XSS test payloads.

The engine is the single entry point for anything payload-related.  It reads
base payloads from bundled or user-supplied files, optionally applies the
mutation pass, appends WAF-bypass variants, enforces the configured cap, and
returns a deduplicated list ready for injection.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

from core.config import PayloadConfig
from payloads.generator import PayloadGenerator

logger = logging.getLogger(__name__)

# Bundled payload data lives alongside this package
_DATA_DIR = Path(__file__).parent / "data"


class PayloadEngine:
    """
    Central payload manager for the XSS framework.

    Instantiate once per scan session; call :meth:`load` to retrieve the
    final payload list.

    Args:
        config: :class:`~core.config.PayloadConfig` controlling mutations,
                WAF-bypass inclusion, and maximum payload count.
    """

    def __init__(self, config: PayloadConfig) -> None:
        self._config = config
        self._generator = PayloadGenerator()

    def load(self, custom_file: Optional[Path] = None) -> list[str]:
        """
        Build and return the complete payload list for a scan session.

        Processing order:
        1. Load base payloads (bundled or from *custom_file*).
        2. Apply mutation pass if enabled.
        3. Append WAF-bypass payloads if enabled.
        4. Deduplicate, preserving order.
        5. Slice to ``max_payloads`` if configured.

        Args:
            custom_file: Optional path to a user-supplied TXT or JSON file.
                         When provided, replaces the bundled base payloads.

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
            bypass = self._load_file(_DATA_DIR / "waf_bypass.txt")
            payloads = list(dict.fromkeys(payloads + bypass))
            logger.debug("WAF-bypass variants loaded; total: %d", len(payloads))

        if self._config.max_payloads is not None:
            payloads = payloads[: self._config.max_payloads]

        logger.info("Payload engine ready: %d payloads", len(payloads))
        return payloads

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _load_bundled(self) -> list[str]:
        """Load the framework's built-in base payload set."""
        path = _DATA_DIR / "base_payloads.txt"
        payloads = self._load_file(path)
        logger.debug("Loaded %d bundled base payloads", len(payloads))
        return payloads

    @staticmethod
    def _load_file(path: Path) -> list[str]:
        """
        Read payloads from *path*.

        Supports:
        - ``.txt``: one payload per line; lines starting with ``#`` are skipped.
        - ``.json``: root-level JSON array of strings.

        Args:
            path: Payload file path.

        Returns:
            Deduplicated list of non-empty payload strings.

        Raises:
            ValueError: If a JSON file does not contain a top-level array.
        """
        if not path.exists():
            logger.error("Payload file not found: %s", path)
            return []

        text = path.read_text(encoding="utf-8")

        if path.suffix.lower() == ".json":
            data = json.loads(text)
            if not isinstance(data, list):
                raise ValueError(f"JSON payload file must contain a root-level array: {path}")
            payloads = [str(p) for p in data if p]
        else:
            payloads = [
                line.strip()
                for line in text.splitlines()
                if line.strip() and not line.startswith("#")
            ]

        return list(dict.fromkeys(payloads))  # deduplicate, preserve order
