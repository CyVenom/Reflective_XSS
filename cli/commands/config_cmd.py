"""``xsf config`` — configuration management sub-commands."""
from __future__ import annotations

import dataclasses
from pathlib import Path
from typing import Optional

import typer
from rich import box
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cli.console import CONSOLE
from core.config import FrameworkConfig

app = typer.Typer(
    help="Configuration management — init, display, and validate config files.",
    rich_markup_mode="rich",
)

_DEFAULT_CONFIG = """\
# XSS Framework — Configuration File
# All values shown are defaults. Remove any section to use framework defaults.

scanner:
  concurrency: 10       # Concurrent request limit
  timeout: 10.0         # Per-request timeout in seconds
  max_retries: 3        # Retry failed requests this many times
  retry_delay: 1.0      # Base delay between retries (doubles each attempt)
  verify_ssl: false     # Set true to enforce TLS certificate validation
  follow_redirects: true

crawler:
  max_depth: 2          # Link-following depth from seed URL
  max_pages: 50         # Hard cap on crawled pages
  concurrency: 5        # Concurrent page-fetch workers
  rate_limit: 10.0      # Max requests per second
  follow_external: false
  respect_robots: true  # Honour robots.txt disallow rules
  js_extraction: true   # Mine JS source for endpoint URLs
  parameter_mining: true

payloads:
  use_mutations: true       # Auto-mutate base payloads
  use_waf_bypass: false     # Include WAF-bypass variants (opt-in)
  use_encoding_mutations: false
  max_payloads: null        # null = no cap

reporting:
  verbose: false            # Show payload + evidence in console output
  color: true               # Enable Rich colour output

logging:
  level: WARNING            # DEBUG | INFO | WARNING | ERROR
  file: null                # Log file path (null = stderr)
"""


@app.command("init")
def init_config(
    output: Path = typer.Argument(Path("xsf.yaml"), help="Config file to create."),
    force: bool = typer.Option(False, "--force", help="Overwrite if the file already exists."),
) -> None:
    """Create a new config file pre-populated with all defaults.

    \b
    Examples:
      xsf config init
      xsf config init my-target.yaml
      xsf config init xsf.yaml --force
    """
    if output.exists() and not force:
        CONSOLE.print(
            f"[warning]File already exists: {output}  (use --force to overwrite)[/warning]"
        )
        raise typer.Exit(1)

    output.write_text(_DEFAULT_CONFIG, encoding="utf-8")
    CONSOLE.print(f"\n[success]Config file created: {output}[/success]")
    CONSOLE.print(f"[muted]  Pass it to any command with: --config {output}[/muted]")


@app.command("show")
def show_config(
    config_file: Optional[Path] = typer.Argument(
        None, help="YAML config file (omit to show framework defaults)."
    ),
) -> None:
    """Display resolved configuration values.

    \b
    Examples:
      xsf config show
      xsf config show xsf.yaml
    """
    if config_file:
        if not config_file.exists():
            CONSOLE.print(f"[error]Config file not found: {config_file}[/error]")
            raise typer.Exit(1)
        cfg    = FrameworkConfig.from_yaml(config_file)
        source = str(config_file)
    else:
        cfg    = FrameworkConfig.default()
        source = "framework defaults"

    def _section_table(title: str, obj: object) -> Table:
        t = Table(
            title=title,
            box=box.SIMPLE,
            border_style="dim",
            header_style="bold cyan",
        )
        t.add_column("Key",   style="bold", no_wrap=True)
        t.add_column("Value", style="yellow")
        for f in dataclasses.fields(obj):  # type: ignore[arg-type]
            val = getattr(obj, f.name)
            t.add_row(f.name, str(val) if val is not None else "[dim]null[/dim]")
        return t

    CONSOLE.print(Panel(
        f"[dim]Source: {source}[/dim]",
        title=Text("  CONFIGURATION  ", style="bold white on dark_red"),
        border_style="red",
        box=box.ROUNDED,
    ))
    CONSOLE.print(_section_table("Scanner",   cfg.scanner))
    CONSOLE.print(_section_table("Crawler",   cfg.crawler))
    CONSOLE.print(_section_table("Payloads",  cfg.payloads))
    CONSOLE.print(_section_table("Reporting", cfg.reporting))
    CONSOLE.print(_section_table("Logging",   cfg.logging))


@app.command("validate")
def validate_config(
    config_file: Path = typer.Argument(..., help="YAML config file to validate."),
) -> None:
    """Validate a YAML configuration file for structural and logical errors.

    \b
    Examples:
      xsf config validate xsf.yaml
    """
    if not config_file.exists():
        CONSOLE.print(f"[error]File not found: {config_file}[/error]")
        raise typer.Exit(1)

    try:
        cfg = FrameworkConfig.from_yaml(config_file)
    except Exception as exc:
        CONSOLE.print(f"[error]Parse error:[/error] {exc}")
        raise typer.Exit(1)

    errors:   list[str] = []
    warnings: list[str] = []

    if cfg.scanner.concurrency < 1:
        errors.append("scanner.concurrency must be >= 1")
    if cfg.scanner.timeout <= 0:
        errors.append("scanner.timeout must be > 0")
    if cfg.scanner.max_retries < 0:
        errors.append("scanner.max_retries must be >= 0")
    if cfg.crawler.max_depth < 0:
        errors.append("crawler.max_depth must be >= 0")
    if cfg.crawler.max_pages < 1:
        errors.append("crawler.max_pages must be >= 1")
    if cfg.scanner.concurrency > 50:
        warnings.append("scanner.concurrency > 50 may trigger rate-limiting on the target")
    if cfg.crawler.max_pages > 500:
        warnings.append("crawler.max_pages > 500 may result in very long crawl times")

    if errors:
        CONSOLE.print(f"\n[error]  {len(errors)} validation error(s):[/error]")
        for e in errors:
            CONSOLE.print(f"  [red]✗[/red] {e}")
        raise typer.Exit(1)

    if warnings:
        CONSOLE.print(f"\n[warning]  {len(warnings)} warning(s):[/warning]")
        for w in warnings:
            CONSOLE.print(f"  [yellow]![/yellow] {w}")

    CONSOLE.print(f"\n[success]  {config_file} — configuration is valid.[/success]")
