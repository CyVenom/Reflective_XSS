"""
XSS Framework — Command-line interface.

Entry point for the ``xsf`` command.  Provides three sub-commands:

``xsf scan``               — Scan a target URL for reflected XSS
``xsf generate-payloads``  — Export the payload list to a file
``xsf list-modules``       — Show all available scanning modules
"""

from __future__ import annotations

import asyncio
import logging
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

from core.config import FrameworkConfig
from modules.xss.reflective import ReflectiveXSSModule
from reports.console import ConsoleReporter
from reports.json_reporter import JSONReporter
from utils.logging_setup import setup_logging

console = Console()

_BANNER = """\
[bold red]
__  ______ ______ _____                                     _
\\ \\/ / ___/ ___/ ___| __ __ _ _ __ ___   _____      _____ _ __| | __
 \\  /\\__ \\\\___ \\___ \\| '__/ _` | '_ ` _ \\ / _ \\ \\ /\\ / / _ \\ '__|   <
 /  \\___) |__) |__) | | | (_| | | | | | |  __/\\ V  V /  __/ |  | . \\
/_/\\_\\____/____/____/|_|  \\__,_|_| |_| |_|\\___| \\_/\\_/ \\___|_|  |_|\\_\\
[/bold red]
[dim]  Professional Reflective XSS Testing Framework  ·  v1.0.0[/dim]
"""


# ---------------------------------------------------------------------------
# CLI root group
# ---------------------------------------------------------------------------


@click.group(
    context_settings={"help_option_names": ["-h", "--help"], "max_content_width": 100},
    invoke_without_command=True,
)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """XSS Framework — Professional Reflected XSS Testing."""
    if ctx.invoked_subcommand is None:
        console.print(_BANNER)
        click.echo(ctx.get_help())


# ---------------------------------------------------------------------------
# scan sub-command
# ---------------------------------------------------------------------------


@cli.command("scan")
# Target
@click.option("-u", "--url",        required=True,  help="Target URL (include query parameters for direct testing).")
# Scan mode
@click.option("-f", "--forms",      is_flag=True,   default=False, help="Discover and test HTML forms on the target page.")
@click.option("-c", "--crawl",      is_flag=True,   default=False, help="Crawl the target site for additional endpoints before scanning.")
# Payloads
@click.option("-p", "--payloads",   "payload_file", default=None,  type=click.Path(exists=True), help="Custom payload file (TXT or JSON).")
@click.option("--waf-bypass",       is_flag=True,   default=False, help="Append WAF-bypass payload variants.")
# HTTP
@click.option("--concurrency",      default=10,     show_default=True, help="Concurrent request limit.")
@click.option("--timeout",          default=10.0,   show_default=True, help="Per-request timeout (seconds).")
@click.option("--retries",          default=3,      show_default=True, help="Max retries per failed request.")
@click.option("--verify-ssl",       is_flag=True,   default=False, help="Verify TLS certificates (disabled by default for lab targets).")
# Config file
@click.option("--config",           "config_file",  default=None,  type=click.Path(exists=True), help="YAML configuration file.")
# Output
@click.option("-o", "--output",     default=None,   help="Write JSON report to this file path.")
@click.option("--format",           "output_format",default="console", type=click.Choice(["console", "json"]), show_default=True, help="Output format.")
@click.option("-v", "--verbose",    is_flag=True,   default=False, help="Show payload details and evidence snippets.")
# Logging
@click.option("--log-level",        default="WARNING", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"]), show_default=True)
@click.option("--log-file",         default=None,   help="Write framework logs to a file.")
def scan(
    url: str,
    forms: bool,
    crawl: bool,
    payload_file: Optional[str],
    waf_bypass: bool,
    concurrency: int,
    timeout: float,
    retries: int,
    verify_ssl: bool,
    config_file: Optional[str],
    output: Optional[str],
    output_format: str,
    verbose: bool,
    log_level: str,
    log_file: Optional[str],
) -> None:
    """Scan a URL for Reflected XSS vulnerabilities."""
    setup_logging(level=log_level, log_file=log_file)
    console.print(_BANNER)

    # ------------------------------------------------------------------
    # Build configuration (YAML base → CLI overrides)
    # ------------------------------------------------------------------
    if config_file:
        cfg = FrameworkConfig.from_yaml(Path(config_file))
    else:
        cfg = FrameworkConfig.default()

    cfg.scanner.concurrency  = concurrency
    cfg.scanner.timeout      = timeout
    cfg.scanner.max_retries  = retries
    cfg.scanner.verify_ssl   = verify_ssl
    cfg.payloads.use_waf_bypass = waf_bypass
    cfg.reporting.verbose    = verbose
    cfg.reporting.format     = output_format
    if output:
        cfg.reporting.output_file = output

    # ------------------------------------------------------------------
    # Run the module
    # ------------------------------------------------------------------
    module = ReflectiveXSSModule(cfg)

    try:
        result = asyncio.run(
            module.run(
                url,
                scan_forms=forms,
                crawl=crawl,
                payload_file=payload_file,
            )
        )
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        sys.exit(130)
    except Exception as exc:
        console.print(f"\n[bold red]Fatal error:[/bold red] {exc}")
        logging.getLogger(__name__).exception("Fatal error during scan")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------
    if output_format == "json":
        JSONReporter(output_file=output).report(result)
    else:
        ConsoleReporter(verbose=verbose, color=cfg.reporting.color).report(result)
        # Always produce a JSON sidecar when --output is specified
        if output:
            JSONReporter(output_file=output).report(result)

    sys.exit(0 if not result.findings else 1)


# ---------------------------------------------------------------------------
# generate-payloads sub-command
# ---------------------------------------------------------------------------


@cli.command("generate-payloads")
@click.option("-o", "--output",     required=True,  help="Output file path (.txt or .json).")
@click.option("--count",            default=None,   type=int, help="Cap the output at N payloads.")
@click.option("--waf-bypass",       is_flag=True,   default=False, help="Include WAF-bypass variants.")
@click.option("--no-mutations",     is_flag=True,   default=False, help="Skip the mutation pass.")
def generate_payloads(
    output: str,
    count: Optional[int],
    waf_bypass: bool,
    no_mutations: bool,
) -> None:
    """Generate and export the XSS payload list to a file."""
    import json as _json
    from core.config import PayloadConfig
    from payloads.engine import PayloadEngine

    cfg = PayloadConfig(
        use_mutations=not no_mutations,
        use_waf_bypass=waf_bypass,
        max_payloads=count,
    )
    engine = PayloadEngine(cfg)
    payloads = engine.load()

    out_path = Path(output)
    if out_path.suffix.lower() == ".json":
        out_path.write_text(_json.dumps(payloads, indent=2), encoding="utf-8")
    else:
        out_path.write_text("\n".join(payloads), encoding="utf-8")

    console.print(f"[green][+] Exported {len(payloads)} payloads → {out_path}[/green]")


# ---------------------------------------------------------------------------
# list-modules sub-command
# ---------------------------------------------------------------------------


@cli.command("list-modules")
def list_modules() -> None:
    """List all available scanning modules."""
    from rich import box
    from rich.table import Table

    table = Table(
        title="Available Modules",
        box=box.ROUNDED,
        border_style="dim",
        header_style="bold cyan",
    )
    table.add_column("Module",      style="bold cyan", no_wrap=True)
    table.add_column("Version",     style="dim",       no_wrap=True)
    table.add_column("Description")

    # Register modules here as the framework grows
    _MODULES = [ReflectiveXSSModule]
    for cls in _MODULES:
        table.add_row(cls.name, cls.version, cls.description)

    console.print()
    console.print(table)
    console.print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Package entry point (registered as ``xsf`` in pyproject.toml)."""
    cli()


if __name__ == "__main__":
    main()
