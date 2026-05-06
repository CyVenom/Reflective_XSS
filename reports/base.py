"""Abstract reporter interface."""

from __future__ import annotations

import abc

from modules.base import ModuleResult


class BaseReporter(abc.ABC):
    """
    Abstract base class for all output reporters.

    Implement :meth:`report` to render :class:`~modules.base.ModuleResult`
    objects in a specific format (console, JSON, HTML, etc.).

    Adding a new reporter requires only:
    1. Subclass :class:`BaseReporter`.
    2. Implement :meth:`report`.
    3. Wire it into :mod:`cli.main`.
    """

    @abc.abstractmethod
    def report(self, result: ModuleResult) -> None:
        """
        Render *result* in the reporter's output format.

        Args:
            result: The aggregated scan result from a module run.
        """
