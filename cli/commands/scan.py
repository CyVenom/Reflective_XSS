"""``xsf scan`` — reflective XSS scanning command."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cli.console import BANNER, CONSOLE, finding_panel
from core.config import FrameworkConfig
from modules.xss.reflective import ReflectiveXSSModule
from reports.session import ScanSession
from utils.logging_setup import setup_logging


def scan(
    url: str = typer.Argument(..., help="Target URL (include ?param=value for direct testing)."),
    forms: bool = typer.Option(False, "--forms", "-f", help="Discover and test HTML forms on the target."),
    do_crawl: bool = typer.Option(False, "--crawl", "-c", help="Crawl the site before scanning."),
    depth: int = typer.Option(2, "--depth", help="Crawl depth (requires --crawl).", show_default=True),
    max_pages: int = typer.Option(50, "--max-pages", help="Max pages to crawl.", show_default=True),
    payload_file: Optional[Path] = typer.Option(None, "--payloads", "-p", help="Custom payload file (.txt/.json/.yaml)."),
    waf_bypass: bool = typer.Option(False, "--waf-bypass", help="Append WAF-bypass payload variants."),
    encoding_mutations: bool = typer.Option(False, "--mutations", help="Apply encoding mutation pass."),
    concurrency: int = typer.Option(10, "--concurrency", help="Concurrent request limit.", show_default=True),
    timeout: float = typer.Option(10.0, "--timeout", help="Per-request timeout in seconds.", show_default=True),
    retries: int = typer.Option(3, "--retries", help="Max retries per request.", show_default=True),
    verify_ssl: bool = typer.Option(False, "--verify-ssl", help="Enable TLS certificate verification."),
    config_file: Optional[Path] = typer.Option(None, "--config", help="YAML configuration file."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Save report to this file."),
    output_format: str = typer.Option("json", "--format", help="Report format: json | html | csv", show_default=True),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show payload and evidence details."),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug logging."),
    log_file: Optional[Path] = typer.Option(None, "--log-file", help="Write framework logs to file."),
) -> None:
    """Scan a URL for Reflected XSS vulnerabilities.

    \b
    Examples:
      xsf scan "https://target.com/search?q=test"
      xsf scan "https://target.com" --forms --crawl --waf-bypass -v
      xsf scan "https://target.com/page?q=test" -o report.html --format html
    """
    CONSOLE.print(BANNER)
    setup_logging(
        level="DEBUG" if debug else "WARNING",
        log_file=str(log_file) if log_file else None,
    )

    # Build config
    if config_file:
        cfg = FrameworkConfig.from_yaml(config_file)
    else:
        cfg = FrameworkConfig.default()

    cfg.scanner.concurrency          = concurrency
    cfg.scanner.timeout              = timeout
    cfg.scanner.max_retries          = retries
    cfg.scanner.verify_ssl           = verify_ssl
    cfg.crawler.max_depth            = depth
    cfg.crawler.max_pages            = max_pages
    cfg.payloads.use_waf_bypass      = waf_bypass
    cfg.payloads.use_encoding_mutations = encoding_mutations
    cfg.reporting.verbose            = verbose

    # Scan mode summary
    mode_parts = ["url-params"]
    if forms:
        mode_parts.append("forms")
    if do_crawl:
        mode_parts.append(f"crawl(depth={depth}, max={max_pages})")

    flag_waf  = "[green]on[/green]" if waf_bypass else "[dim]off[/dim]"
    flag_mut  = "[green]on[/green]" if encoding_mutations else "[dim]off[/dim]"
    flag_ssl  = "[green]verify[/green]" if verify_ssl else "[dim]skip[/dim]"

    info_body = (
        f"[bold]Target       :[/bold] [cyan]{url}[/cyan]\n"
        f"[bold]Scan mode    :[/bold] {' + '.join(mode_parts)}\n"
        f"[bold]Concurrency  :[/bold] {concurrency}  "
        f"[bold]Timeout:[/bold] {timeout}s  "
        f"[bold]Retries:[/bold] {retries}  "
        f"[bold]SSL:[/bold] {flag_ssl}\n"
        f"[bold]WAF bypass   :[/bold] {flag_waf}  "
        f"[bold]Mutations:[/bold] {flag_mut}"
        + (f"\n[bold]Payload file :[/bold] [dim]{payload_file}[/dim]" if payload_file else "")
        + (f"\n[bold]Config file  :[/bold] [dim]{config_file}[/dim]" if config_file else "")
    )
    CONSOLE.print(Panel(
        info_body,
        title=Text("  TARGET  ", style="bold white on dark_red"),
        border_style="red",
        box=box.ROUNDED,
    ))

    # Run the scan
    module  = ReflectiveXSSModule(cfg)
    session = ScanSession.start(scan_options={
        "target":       url,
        "forms":        forms,
        "crawl":        do_crawl,
        "waf_bypass":   waf_bypass,
        "mutations":    encoding_mutations,
        "concurrency":  concurrency,
        "timeout":      timeout,
        "verify_ssl":   verify_ssl,
    })
    try:
        with CONSOLE.status("[bold yellow]  Scanning for reflected XSS…", spinner="dots"):
            start = time.perf_counter()
            result = asyncio.run(
                module.run(
                    url,
                    scan_forms=forms,
                    crawl=do_crawl,
                    payload_file=str(payload_file) if payload_file else None,
                )
            )
            elapsed = time.perf_counter() - start
    except KeyboardInterrupt:
        CONSOLE.print("\n[yellow]  Scan interrupted by user.[/yellow]")
        raise typer.Exit(130)
    except Exception as exc:
        CONSOLE.print(f"\n[bold red]  Fatal error:[/bold red] {exc}")
        if debug:
            CONSOLE.print_exception()
        raise typer.Exit(1)

    session.finish()
    result.metadata["session"] = session.to_dict()

    # Print findings immediately
    finding_count = len(result.findings)
    if finding_count:
        noun = "VULNERABILITIES" if finding_count != 1 else "VULNERABILITY"
        CONSOLE.print(f"\n[bold red]  {finding_count} {noun} CONFIRMED[/bold red]\n")
        for idx, finding in enumerate(result.findings, start=1):
            CONSOLE.print(finding_panel(finding, idx, verbose=verbose))
    else:
        CONSOLE.print("\n[bold green]  No vulnerabilities detected.[/bold green]")

    # Summary panel
    payloads_tested = result.metadata.get("payloads_tested", 0)
    params_tested   = result.metadata.get("parameters_tested", 0)
    payloads_loaded = result.metadata.get("payloads_loaded", 0)
    error_count     = len(result.errors)

    vuln_style  = "red"    if finding_count else "green"
    error_style = "yellow" if error_count  else "dim"

    stats = Table.grid(padding=(0, 3))
    stats.add_column(style="bold")
    stats.add_column()
    stats.add_row("Payloads loaded",   str(payloads_loaded))
    stats.add_row("Payloads tested",   str(payloads_tested))
    stats.add_row("Parameters tested", str(params_tested))
    stats.add_row(
        "Vulnerabilities",
        f"[{vuln_style}]{finding_count}[/{vuln_style}]",
    )
    stats.add_row(
        "Errors",
        f"[{error_style}]{error_count}[/{error_style}]",
    )
    stats.add_row("Elapsed",           f"{elapsed:.2f}s")

    CONSOLE.print(Panel(
        stats,
        title=Text("  SCAN SUMMARY  ", style="bold white on dark_red"),
        border_style=vuln_style,
        box=box.ROUNDED,
    ))

    # Save report
    if output:
        fmt = output_format.lower()
        if fmt == "html":
            from reports.html_reporter import HTMLReporter
            HTMLReporter(str(output)).report(result)
        elif fmt == "csv":
            from reports.csv_reporter import CSVReporter
            CSVReporter(str(output)).report(result)
        else:
            from reports.json_reporter import JSONReporter
            JSONReporter(str(output)).report(result)
        CONSOLE.print(f"\n[success]  Report saved → {output}[/success]")

    if result.errors and verbose:
        CONSOLE.print(
            f"\n[muted]  {error_count} request error(s) encountered. "
            "Use --debug for details.[/muted]"
        )

    raise typer.Exit(1 if finding_count else 0)
