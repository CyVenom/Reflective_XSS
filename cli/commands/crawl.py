"""``xsf crawl`` — site crawler command."""
from __future__ import annotations

import asyncio
import json as _json
import time
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cli.console import BANNER, CONSOLE
from core.config import FrameworkConfig
from core.crawler import Crawler
from utils.http import HTTPClient
from utils.logging_setup import setup_logging


def crawl(
    url: str = typer.Argument(..., help="Seed URL to start crawling from."),
    depth: int = typer.Option(2, "--depth", help="Maximum crawl depth.", show_default=True),
    max_pages: int = typer.Option(50, "--max-pages", help="Maximum pages to crawl.", show_default=True),
    concurrency: int = typer.Option(5, "--concurrency", help="Concurrent fetch workers.", show_default=True),
    rate_limit: float = typer.Option(10.0, "--rate-limit", help="Max requests per second.", show_default=True),
    no_robots: bool = typer.Option(False, "--no-robots", help="Ignore robots.txt."),
    no_js: bool = typer.Option(False, "--no-js", help="Skip JS endpoint extraction."),
    no_params: bool = typer.Option(False, "--no-params", help="Skip parameter mining."),
    follow_external: bool = typer.Option(False, "--follow-external", help="Follow off-domain links."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save results as JSON."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print all discovered URLs."),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging."),
) -> None:
    """Crawl a site and discover endpoints, forms, and injectable parameters.

    \b
    Examples:
      xsf crawl "https://target.com"
      xsf crawl "https://target.com" --depth 3 --max-pages 100 -v
      xsf crawl "https://target.com" -o endpoints.json
    """
    CONSOLE.print(BANNER)
    setup_logging(level="DEBUG" if debug else "WARNING")

    cfg = FrameworkConfig.default()
    cfg.crawler.max_depth        = depth
    cfg.crawler.max_pages        = max_pages
    cfg.crawler.concurrency      = concurrency
    cfg.crawler.rate_limit       = rate_limit
    cfg.crawler.respect_robots   = not no_robots
    cfg.crawler.js_extraction    = not no_js
    cfg.crawler.parameter_mining = not no_params
    cfg.crawler.follow_external  = follow_external

    robots_flag = "[green]respected[/green]" if not no_robots else "[yellow]ignored[/yellow]"
    js_flag     = "[green]on[/green]" if not no_js    else "[dim]off[/dim]"
    params_flag = "[green]on[/green]" if not no_params else "[dim]off[/dim]"

    CONSOLE.print(Panel(
        f"[bold]Seed URL       :[/bold] [cyan]{url}[/cyan]\n"
        f"[bold]Depth          :[/bold] {depth}  "
        f"[bold]Max pages:[/bold] {max_pages}  "
        f"[bold]Concurrency:[/bold] {concurrency}\n"
        f"[bold]Rate limit     :[/bold] {rate_limit} req/s  "
        f"[bold]robots.txt:[/bold] {robots_flag}\n"
        f"[bold]JS extraction  :[/bold] {js_flag}  "
        f"[bold]Param mining:[/bold] {params_flag}  "
        f"[bold]External:[/bold] {'[yellow]yes[/yellow]' if follow_external else '[dim]no[/dim]'}",
        title=Text("  CRAWL  ", style="bold white on dark_red"),
        border_style="red",
        box=box.ROUNDED,
    ))

    async def _run():
        async with HTTPClient(cfg.scanner) as http:
            return await Crawler(cfg.crawler, http).crawl(url)

    try:
        with CONSOLE.status("[bold yellow]  Crawling…", spinner="dots"):
            start = time.perf_counter()
            crawl_result = asyncio.run(_run())
            elapsed = time.perf_counter() - start
    except KeyboardInterrupt:
        CONSOLE.print("\n[yellow]  Crawl interrupted.[/yellow]")
        raise typer.Exit(130)
    except Exception as exc:
        CONSOLE.print(f"\n[bold red]  Error:[/bold red] {exc}")
        if debug:
            CONSOLE.print_exception()
        raise typer.Exit(1)

    param_urls = crawl_result.urls_with_params
    visited    = crawl_result.visited
    forms      = crawl_result.forms
    js_eps     = crawl_result.js_endpoints
    errors     = crawl_result.errors

    # Verbose: list every visited URL
    if verbose and visited:
        url_table = Table(
            title=f"Visited URLs ({len(visited)})",
            box=box.SIMPLE,
            border_style="dim",
            header_style="bold cyan",
        )
        url_table.add_column("URL")
        for u in sorted(visited):
            url_table.add_row(u)
        CONSOLE.print()
        CONSOLE.print(url_table)

    # Injectable endpoints table
    if param_urls:
        param_table = Table(
            title=f"Injectable Endpoints ({len(param_urls)})",
            box=box.ROUNDED,
            border_style="yellow",
            header_style="bold yellow",
        )
        param_table.add_column("URL with Parameters")
        for u in param_urls:
            param_table.add_row(u)
        CONSOLE.print()
        CONSOLE.print(param_table)

    # Forms table
    if forms:
        form_table = Table(
            title=f"Discovered Forms ({len(forms)})",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
        )
        form_table.add_column("Action")
        form_table.add_column("Method", width=8)
        form_table.add_column("Injectable Fields")
        for form in forms:
            injectable = [f.name for f in form.injectable_fields()]
            all_fields = [f.name for f in form.fields]
            field_str  = ", ".join(injectable) if injectable else "[dim]" + ", ".join(all_fields) + "[/dim]"
            form_table.add_row(form.action, form.method.upper(), field_str)
        CONSOLE.print()
        CONSOLE.print(form_table)

    # JS endpoints table
    if js_eps and verbose:
        js_table = Table(
            title=f"JS Endpoints ({len(js_eps)})",
            box=box.SIMPLE,
            border_style="dim",
            header_style="bold dim",
        )
        js_table.add_column("URL")
        js_table.add_column("Source Page", style="dim")
        for ep in js_eps:
            js_table.add_row(ep.url, ep.source_page)
        CONSOLE.print()
        CONSOLE.print(js_table)

    # Summary
    stats = Table.grid(padding=(0, 3))
    stats.add_column(style="bold")
    stats.add_column()
    stats.add_row("Pages visited",    str(len(visited)))
    stats.add_row("Injectable URLs",  f"[yellow]{len(param_urls)}[/yellow]")
    stats.add_row("Forms found",      f"[cyan]{len(forms)}[/cyan]")
    stats.add_row("JS endpoints",     str(len(js_eps)))
    stats.add_row("Errors",           f"[{'yellow' if errors else 'dim'}]{len(errors)}[/{'yellow' if errors else 'dim'}]")
    stats.add_row("Elapsed",          f"{elapsed:.2f}s")

    CONSOLE.print(Panel(
        stats,
        title=Text("  CRAWL SUMMARY  ", style="bold white on dark_red"),
        border_style="green",
        box=box.ROUNDED,
    ))

    if output:
        data = {
            "seed_url":        url,
            "pages_visited":   len(visited),
            "urls_with_params": param_urls,
            "forms": [
                {
                    "action": f.action,
                    "method": f.method,
                    "fields": [{"name": ff.name, "type": ff.input_type} for ff in f.fields],
                }
                for f in forms
            ],
            "js_endpoints": [{"url": ep.url, "source_page": ep.source_page} for ep in js_eps],
            "errors": errors,
        }
        output.write_text(_json.dumps(data, indent=2), encoding="utf-8")
        CONSOLE.print(f"\n[success]  Results saved → {output}[/success]")
