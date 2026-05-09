"""``xsf payloads`` — payload management sub-commands."""
from __future__ import annotations

import json as _json
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.table import Table
from rich.text import Text

from cli.console import CONSOLE, SEVERITY_STYLES
from core.config import PayloadConfig
from payloads.engine import PayloadEngine
from payloads.models import PayloadCategory

app = typer.Typer(
    help="Payload management — list categories, inspect payloads, and export sets.",
    rich_markup_mode="rich",
)

_CAT_DESCRIPTIONS: dict[PayloadCategory, str] = {
    PayloadCategory.BASIC:               "Classic script injection and event handler payloads",
    PayloadCategory.POLYGLOT:            "Multi-context payloads that fire across several injection points",
    PayloadCategory.WAF_BYPASS:          "Obfuscated payloads designed to evade WAF pattern matching",
    PayloadCategory.ATTRIBUTE_INJECTION: "Attribute breakout and same-tag event handler injections",
    PayloadCategory.JS_CONTEXT:          "Payloads targeting injection inside JavaScript code blocks",
    PayloadCategory.SVG:                 "SVG-namespace XSS vectors",
    PayloadCategory.CUSTOM:              "User-supplied custom payloads",
}


@app.command("list")
def list_payloads(
    waf_bypass: bool = typer.Option(False, "--waf-bypass", help="Include WAF-bypass category."),
) -> None:
    """List all payload categories with entry counts.

    \b
    Examples:
      xsf payloads list
      xsf payloads list --waf-bypass
    """
    cfg = PayloadConfig(use_waf_bypass=waf_bypass, use_mutations=False)
    engine = PayloadEngine(cfg)

    table = Table(
        title="Payload Categories",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold white on dark_red",
        show_lines=True,
    )
    table.add_column("Category",    style="bold cyan",   no_wrap=True)
    table.add_column("Count",       style="bold yellow", justify="right", width=7)
    table.add_column("Description", style="dim")

    total = 0
    for cat in PayloadCategory:
        if cat == PayloadCategory.CUSTOM:
            continue
        if cat == PayloadCategory.WAF_BYPASS and not waf_bypass:
            continue
        entries = engine.load_entries(categories=[cat])
        n = len(entries)
        total += n
        table.add_row(cat.value, str(n), _CAT_DESCRIPTIONS.get(cat, ""))

    table.add_section()
    table.add_row("[bold]TOTAL[/bold]", f"[bold]{total}[/bold]", "")

    CONSOLE.print()
    CONSOLE.print(table)
    CONSOLE.print()


@app.command("show")
def show_payloads(
    category: str = typer.Argument(..., help="Category name: basic, svg, waf_bypass, …"),
    tag: Optional[str] = typer.Option(None, "--tag", "-t", help="Filter by tag substring."),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter: high | medium | low"),
    limit: int = typer.Option(50, "--limit", "-n", help="Max entries to display.", show_default=True),
    no_truncate: bool = typer.Option(False, "--no-truncate", help="Show full payload text."),
) -> None:
    """Show payloads in a category, with optional tag/severity filtering.

    \b
    Examples:
      xsf payloads show basic
      xsf payloads show waf_bypass --severity high
      xsf payloads show js_context --tag template-literal
    """
    try:
        cat = PayloadCategory(category.lower())
    except ValueError:
        valid = ", ".join(c.value for c in PayloadCategory if c != PayloadCategory.CUSTOM)
        CONSOLE.print(f"[error]Unknown category [bold]{category!r}[/bold]. Valid: {valid}[/error]")
        raise typer.Exit(1)

    cfg = PayloadEngine(PayloadConfig(use_waf_bypass=True, use_mutations=False))
    entries = cfg.load_entries(categories=[cat])

    if tag:
        entries = [e for e in entries if any(tag.lower() in t.lower() for t in e.tags)]
    if severity:
        entries = [e for e in entries if e.severity.lower() == severity.lower()]

    entries = entries[:limit]

    if not entries:
        CONSOLE.print("[warning]No payloads match the specified filters.[/warning]")
        raise typer.Exit(0)

    table = Table(
        title=f"Payloads — [bold]{cat.value}[/bold]  ({len(entries)} shown)",
        box=box.ROUNDED,
        border_style="red",
        header_style="bold white on dark_red",
        show_lines=True,
        expand=True,
    )
    table.add_column("#",           style="dim",   width=4,  no_wrap=True)
    table.add_column("Severity",                   width=10, no_wrap=True)
    table.add_column("Tags",        style="cyan",  width=28)
    table.add_column("Payload",     style="red")
    table.add_column("Description", style="dim")

    for i, entry in enumerate(entries, start=1):
        sev       = entry.severity.upper()
        sev_text  = Text(sev, style=SEVERITY_STYLES.get(sev, "dim"))
        tags_str  = ", ".join(entry.tags)
        text      = entry.text if no_truncate else (
            entry.text[:80] + "…" if len(entry.text) > 80 else entry.text
        )
        table.add_row(str(i), sev_text, tags_str, text, entry.description)

    CONSOLE.print()
    CONSOLE.print(table)
    CONSOLE.print()


@app.command("export")
def export_payloads(
    output: Path = typer.Option(..., "--output", "-o", help="Output file path."),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Export a single category."),
    waf_bypass: bool = typer.Option(False, "--waf-bypass", help="Include WAF-bypass variants."),
    mutations: bool = typer.Option(False, "--mutations", help="Apply mutation pass."),
    count: Optional[int] = typer.Option(None, "--count", "-n", help="Cap output at N payloads."),
    fmt: str = typer.Option("txt", "--format", "-f", help="Output format: txt | json", show_default=True),
) -> None:
    """Export payloads to a TXT or JSON file.

    \b
    Examples:
      xsf payloads export -o payloads.txt
      xsf payloads export -o waf.json --waf-bypass --format json
      xsf payloads export -o basic.txt --category basic
    """
    categories = None
    if category:
        try:
            categories = [PayloadCategory(category.lower())]
        except ValueError:
            CONSOLE.print(f"[error]Unknown category: {category!r}[/error]")
            raise typer.Exit(1)

    cfg = PayloadConfig(use_mutations=mutations, use_waf_bypass=waf_bypass, max_payloads=count)
    engine = PayloadEngine(cfg)
    entries = engine.load_entries(categories=categories)
    texts   = [e.text for e in entries]

    output.parent.mkdir(parents=True, exist_ok=True)
    if fmt.lower() == "json":
        output.write_text(_json.dumps(texts, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        output.write_text("\n".join(texts), encoding="utf-8")

    CONSOLE.print(f"\n[success]Exported {len(texts)} payloads → {output}[/success]")
