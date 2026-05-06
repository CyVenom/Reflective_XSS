"""
Abstract base class for all vulnerability-scanning modules.

Every future module (SQL injection, SSTI, open-redirect, etc.) must subclass
:class:`BaseModule` and implement :meth:`run`.  This contract guarantees that
the CLI, reporting layer, and plugin discovery code all interact with modules
through a stable, typed interface.
"""

from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from typing import Any

from core.config import FrameworkConfig


# ---------------------------------------------------------------------------
# Standardised result container
# ---------------------------------------------------------------------------


@dataclass
class ModuleResult:
    """
    Standardised output container returned by every module's :meth:`run`.

    The ``findings`` list holds dicts whose schema is module-defined; the
    reporting layer must handle whichever keys a module populates.  Common
    keys across all modules:

    ``type``          — vulnerability class (e.g. "Reflected XSS")
    ``severity``      — HIGH | MEDIUM | LOW | INFO
    ``parameter``     — injectable parameter name
    ``payload``       — exact payload that triggered the finding
    ``attack_url``    — reproducible PoC URL or form action
    ``evidence``      — response excerpt confirming the issue
    """

    module_name: str
    target: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def vulnerable(self) -> bool:
        return bool(self.findings)


# ---------------------------------------------------------------------------
# Module interface
# ---------------------------------------------------------------------------


class BaseModule(abc.ABC):
    """
    Abstract base for all framework vulnerability modules.

    Subclasses must declare at minimum :attr:`name`, :attr:`description`, and
    implement :meth:`run`.  The framework uses :attr:`name` for CLI display
    and as a key in JSON reports.

    Example skeleton::

        class SQLiModule(BaseModule):
            name = "sqli"
            description = "Detect SQL injection in URL parameters"
            version = "1.0.0"

            async def run(self, target: str, **kwargs: Any) -> ModuleResult:
                ...
    """

    #: Short identifier used in reports and ``--list-modules`` output.
    name: str = "base"

    #: One-line human-readable description.
    description: str = ""

    #: Semantic version string for this module.
    version: str = "1.0.0"

    def __init__(self, config: FrameworkConfig) -> None:
        self._config = config
        self._logger = logging.getLogger(f"xssframework.modules.{self.name}")

    @abc.abstractmethod
    async def run(self, target: str, **kwargs: Any) -> ModuleResult:
        """
        Execute the module against *target*.

        Args:
            target: The URL or application endpoint to test.
            **kwargs: Module-specific runtime options (e.g. ``scan_forms=True``).

        Returns:
            A :class:`ModuleResult` containing all findings and errors.
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} name={self.name!r} version={self.version!r}>"
