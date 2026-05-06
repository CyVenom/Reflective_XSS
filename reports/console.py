"""
Rich-based console reporter.

Renders scan results as a formatted, colour-coded terminal report.  All visual
output is produced through the `rich` library to support consistent rendering
across platforms and to make it trivially strippable (``color=False``).
"""

from __future__ import annotations

import textwrap

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from modules.base import ModuleResult
from reports.base import BaseReporter

_SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold white on dark_red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim",
}


class ConsoleReporter(BaseReporter):
    """
    Renders :class:`~modules.base.ModuleResult` objects to the terminal.

    Args:
        verbose: When ``True``, each finding also prints its payload and an
                 evidence excerpt from the response body.
        color:   When ``False``, all Rich markup is stripped (CI-friendly).
    """

    def __init__(self, verbose: bool = False, color: bool = True) -> None:
        self._verbose = verbose
        self._console = Console(
            highlight=False,
            markup=True,
            no_color=not color,
        )

    def report(self, result: ModuleResult) -> None:
        """Print the full scan report to the terminal."""
        self._print_header(result)

        if result.findings:
            self._print_findings(result.findings)
        else:
            self._console.print(
                "\n[bold green]  No vulnerabilities detected.[/bold green]\n"
            )

        self._print_summary(result)

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    def _print_header(self, result: ModuleResult) -> None:
        title = Text(
            f" {result.module_name.upper()} ", style="bold white on dark_red"
        )
        body = (
            f"[bold]Target          :[/bold] {result.target}\n"
            f"[bold]Payloads loaded :[/bold] {result.metadata.get('payloads_loaded', 'N/A')}\n"
            f"[bold]Payloads tested :[/bold] {result.metadata.get('payloads_tested', 'N/A')}\n"
            f"[bold]Parameters tested:[/bold] {result.metadata.get('parameters_tested', 'N/A')}"
        )
        self._console.print()
        self._console.print(Panel(body, title=title, border_style="red"))

    def _print_findings(self, findings: list[dict]) -> None:
        count = len(findings)
        self._console.print(
            f"\n[bold red]  {count} VULNERABILITY{'S' if count != 1 else ''} CONFIRMED[/bold red]\n"
        )

        table = Table(
            box=box.ROUNDED,
            border_style="red",
            header_style="bold white on dark_red",
            expand=True,
            show_lines=True,
        )
        table.add_column("#",          style="dim",         width=3,  no_wrap=True)
        table.add_column("Parameter",  style="bold yellow",           no_wrap=True)
        table.add_column("Context",    style="cyan",                  no_wrap=True)
        table.add_column("Severity",                                  no_wrap=True)
        table.add_column("Attack URL")

        for idx, finding in enumerate(findings, start=1):
            severity = finding.get("severity", "HIGH")
            sev_text = Text(severity, style=_SEVERITY_STYLES.get(severity, "bold red"))
            table.add_row(
                str(idx),
                finding.get("parameter", ""),
                finding.get("reflection_context", ""),
                sev_text,
                finding.get("attack_url", ""),
            )

        self._console.print(table)

        if self._verbose:
            self._console.print()
            for idx, finding in enumerate(findings, start=1):
                self._console.rule(f"[bold yellow]Finding #{idx}[/bold yellow]")
                self._console.print(
                    f"  [bold]Payload :[/bold] [red]{finding.get('payload', '')}[/red]"
                )
                evidence = finding.get("evidence", "")
                if evidence:
                    short = textwrap.shorten(evidence, width=200, placeholder="…")
                    self._console.print(f"  [bold]Evidence:[/bold] [dim]{short}[/dim]")
            self._console.print()

    def _print_summary(self, result: ModuleResult) -> None:
        count = len(result.findings)
        style = "bold red" if count else "bold green"
        noun = "vulnerability" if count == 1 else "vulnerabilities"
        self._console.print(
            f"\n[{style}]Scan complete — {count} {noun} found.[/{style}]\n"
        )

        if result.errors:
            self._console.print(
                f"[dim]  {len(result.errors)} request error(s) encountered "
                "(run with --log-level DEBUG for details).[/dim]\n"
            )
