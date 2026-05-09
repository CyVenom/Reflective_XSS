"""
Configuration dataclasses and YAML loader for the XSS framework.

All tuneable parameters live here so that every component receives a typed,
validated configuration object rather than raw dictionaries or environment
variables.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-subsystem configuration dataclasses
# ---------------------------------------------------------------------------


@dataclass
class ScannerConfig:
    """Controls the core async scanning engine."""

    concurrency: int = 10
    """Maximum number of simultaneous HTTP requests."""

    timeout: float = 10.0
    """Per-request timeout in seconds."""

    max_retries: int = 3
    """How many times to retry a failed request before giving up."""

    retry_delay: float = 1.0
    """Base delay in seconds between retries (doubles on each attempt)."""

    follow_redirects: bool = True
    """Whether to follow HTTP 3xx redirects."""

    verify_ssl: bool = False
    """Verify TLS certificates. Disable for self-signed certs on internal targets."""

    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    """User-Agent header sent with every request."""


@dataclass
class CrawlerConfig:
    """Controls the optional web crawler."""

    max_depth: int = 2
    """Maximum link-following depth from the start URL."""

    max_pages: int = 50
    """Hard cap on the total number of pages crawled."""

    concurrency: int = 5
    """Number of concurrent page-fetch workers."""

    rate_limit: float = 10.0
    """Maximum requests per second per domain (0 = unlimited)."""

    follow_external: bool = False
    """Whether to follow links that leave the target's origin."""

    respect_robots: bool = True
    """Honour robots.txt disallow rules."""

    js_extraction: bool = True
    """Scan inline ``<script>`` blocks for endpoint URLs and parameter names."""

    parameter_mining: bool = True
    """Synthesise testable URLs from parameter names mined from page source."""

    timeout: float = 15.0
    """Per-page timeout for crawl requests."""

    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    """User-Agent string used for robots.txt lookups."""


@dataclass
class PayloadConfig:
    """Controls payload loading, mutation, and limits."""

    use_mutations: bool = True
    """Apply automatic mutation passes to expand the base payload list."""

    use_waf_bypass: bool = False
    """Include WAF-bypass payload variants (encoding, obfuscation, etc.)."""

    max_payloads: Optional[int] = None
    """Cap the payload list to this many entries. ``None`` means no limit."""

    categories: list = field(default_factory=list)
    """
    Restrict ``load_entries()`` to specific category names.
    Empty list loads all categories (except WAF_BYPASS unless *use_waf_bypass*).
    Example: ``["basic", "svg"]``
    """

    use_encoding_mutations: bool = False
    """Apply encoding-based mutations (URL, double-URL, HTML entity) via
    :class:`~payloads.generator.AdvancedPayloadMutator` in ``load_entries()``."""

    use_random_generation: bool = False
    """Append randomly-generated payloads to the list in ``load_entries()``."""

    random_count: int = 20
    """Number of random payloads to generate when *use_random_generation* is enabled."""

    tags_filter: list = field(default_factory=list)
    """
    Include only entries whose tags overlap this list in ``load_entries()``.
    Empty list disables tag filtering.
    Example: ``["classic", "svg"]``
    """


@dataclass
class ReportingConfig:
    """Controls how scan results are rendered and saved."""

    format: str = "console"
    """Output format: ``console`` or ``json``."""

    output_file: Optional[str] = None
    """Path to write a JSON report. ``None`` writes to stdout."""

    verbose: bool = False
    """Include payload details and evidence snippets in the console report."""

    color: bool = True
    """Enable Rich terminal colour output."""


@dataclass
class LoggingConfig:
    """Controls the framework's logging subsystem."""

    level: str = "WARNING"
    """Minimum log level: DEBUG, INFO, WARNING, ERROR, CRITICAL."""

    file: Optional[str] = None
    """Optional log file path. Logs go to stderr when not set."""

    format: str = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    """Python logging format string."""


# ---------------------------------------------------------------------------
# Root configuration container
# ---------------------------------------------------------------------------


@dataclass
class FrameworkConfig:
    """
    Aggregated configuration for the entire framework.

    Instantiate with :meth:`default` for sensible defaults, or
    :meth:`from_yaml` to load from a YAML file with per-key overrides.
    """

    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    crawler: CrawlerConfig = field(default_factory=CrawlerConfig)
    payloads: PayloadConfig = field(default_factory=PayloadConfig)
    reporting: ReportingConfig = field(default_factory=ReportingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)

    # ------------------------------------------------------------------
    # Factories
    # ------------------------------------------------------------------

    @classmethod
    def from_yaml(cls, path: Path) -> "FrameworkConfig":
        """
        Load configuration from *path*, merging YAML values over defaults.

        Unknown keys in the YAML file are silently ignored, so a minimal
        config file only needs to specify the values that differ from defaults.

        Args:
            path: Absolute or relative path to the YAML configuration file.

        Returns:
            A fully-populated :class:`FrameworkConfig` instance.
        """
        with open(path, "r", encoding="utf-8") as fh:
            raw: dict = yaml.safe_load(fh) or {}

        cfg = cls()
        _merge(cfg.scanner, raw.get("scanner", {}))
        _merge(cfg.crawler, raw.get("crawler", {}))
        _merge(cfg.payloads, raw.get("payloads", {}))
        _merge(cfg.reporting, raw.get("reporting", {}))
        _merge(cfg.logging, raw.get("logging", {}))

        logger.debug("Loaded configuration from: %s", path)
        return cfg

    @classmethod
    def default(cls) -> "FrameworkConfig":
        """Return a :class:`FrameworkConfig` populated entirely with defaults."""
        return cls()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _merge(target: object, overrides: dict) -> None:
    """Apply *overrides* dict onto a dataclass instance in-place."""
    for key, value in overrides.items():
        if hasattr(target, key) and value is not None:
            setattr(target, key, value)
