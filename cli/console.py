"""Shared Rich console, theme, and display helpers for the XSS Framework CLI."""
from __future__ import annotations

import textwrap

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.theme import Theme

_THEME = Theme({
    "info":     "cyan",
    "warning":  "yellow",
    "error":    "bold red",
    "success":  "bold green",
    "critical": "bold white on dark_red",
    "high":     "bold red",
    "medium":   "bold yellow",
    "low":      "bold cyan",
    "muted":    "dim",
})

CONSOLE = Console(theme=_THEME, highlight=False, markup=True)

BANNER = """\
[bold red]
__  ______ ______ _____                                     _
\\ \\/ / ___/ ___/ ___| __ __ _ _ __ ___   _____      _____ _ __| | __
 \\  /\\__ \\___ \\___ \\| '__/ _` | '_ ` _ \\ / _ \\ \\ /\\ / / _ \\ '__|   <
 /  \\___) |__) |__) | | | (_| | | | | | |  __/\\ V  V /  __/ |  | . \\
/_/\\_\\____/____/____/|_|  \\__,_|_| |_| |_|\\___| \\_/\\_/ \\___|_|  |_|\\_\\[/bold red]
[dim]  Reflective XSS Framework  ·  v1.0.0  ·  Professional Security Testing[/dim]
"""

SEVERITY_STYLES: dict[str, str] = {
    "CRITICAL": "bold white on dark_red",
    "HIGH":     "bold red",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold cyan",
    "INFO":     "dim",
}


def severity_badge(sev: str) -> Text:
    """Return a styled Rich Text severity label."""
    style = SEVERITY_STYLES.get(sev.upper(), "dim")
    return Text(f" {sev.upper()} ", style=style)


def finding_panel(finding: dict, index: int, verbose: bool = True) -> Panel:
    """Render a single finding dict as a Rich Panel."""
    sev       = finding.get("severity", "HIGH").upper()
    param     = finding.get("parameter", "?")
    context   = finding.get("reflection_context", "UNKNOWN")
    payload   = finding.get("payload", "")
    attack_url = finding.get("attack_url", "")
    evidence  = finding.get("evidence", "")
    notes     = finding.get("exploitation_notes", "")

    lines: list[str] = [
        f"[bold]Parameter  :[/bold] [yellow]{param}[/yellow]",
        f"[bold]Context    :[/bold] [cyan]{context}[/cyan]",
        f"[bold]Attack URL :[/bold] [dim]{attack_url}[/dim]",
    ]
    if verbose:
        lines.append(f"[bold]Payload    :[/bold] [red]{payload}[/red]")
        if evidence:
            short = textwrap.shorten(evidence, width=140, placeholder="…")
            lines.append(f"[bold]Evidence   :[/bold] [dim]{short}[/dim]")
        if notes:
            lines.append(f"[bold]Notes      :[/bold] [dim]{notes}[/dim]")

    sev_style = SEVERITY_STYLES.get(sev, "bold red")
    title = Text()
    title.append(f"  FINDING #{index}  ", style="bold white on dark_red")
    title.append("  ")
    title.append(f" {sev} ", style=sev_style)
    return Panel("\n".join(lines), title=title, border_style="red", box=box.ROUNDED)
