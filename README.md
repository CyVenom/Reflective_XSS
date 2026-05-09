<div align="center">

```
██╗  ██╗███████╗███████╗    ███████╗██████╗  █████╗ ███╗   ███╗███████╗██╗    ██╗ ██████╗ ██████╗ ██╗  ██╗
╚██╗██╔╝██╔════╝██╔════╝    ██╔════╝██╔══██╗██╔══██╗████╗ ████║██╔════╝██║    ██║██╔═══██╗██╔══██╗██║ ██╔╝
 ╚███╔╝ ███████╗███████╗    █████╗  ██████╔╝███████║██╔████╔██║█████╗  ██║ █╗ ██║██║   ██║██████╔╝█████╔╝ 
 ██╔██╗ ╚════██║╚════██║    ██╔══╝  ██╔══██╗██╔══██║██║╚██╔╝██║██╔══╝  ██║███╗██║██║   ██║██╔══██╗██╔═██╗ 
██╔╝ ██╗███████║███████║    ██║     ██║  ██║██║  ██║██║ ╚═╝ ██║███████╗╚███╔███╔╝╚██████╔╝██║  ██║██║  ██╗
╚═╝  ╚═╝╚══════╝╚══════╝    ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝ ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
```

**Professional-grade Reflected XSS Detection Framework**

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-345%20passing-brightgreen)](tests/)
[![Async](https://img.shields.io/badge/Async-aiohttp-blueviolet)](https://docs.aiohttp.org)
[![CLI](https://img.shields.io/badge/CLI-Typer%20%2B%20Rich-orange)](https://typer.tiangolo.com)

*A next-generation, async-first XSS framework with DOM-aware reflection analysis, WAF-bypass payload generation, multi-format reporting, and a full benchmark suite.*

</div>

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Usage Examples](#usage-examples)
- [CLI Reference](#cli-reference)
- [Supported Reflection Contexts](#supported-reflection-contexts)
- [Payload System](#payload-system)
- [Reporting](#reporting)
- [Benchmark Results](#benchmark-results)
- [Testing](#testing)
- [Legal Disclaimer](#legal-disclaimer)
- [Contributing](#contributing)
- [Roadmap](#roadmap)
- [License](#license)

---

## Overview

**XSS Framework** (`xsf`) is a modular, async-first security testing tool built for professional penetration testers and security researchers. It goes beyond simple string-matching by performing true DOM-aware reflection analysis — identifying not just *whether* a payload was reflected, but *where* it landed in the page structure, *which characters survived*, and *how difficult exploitation actually is*.

```
Target URL ──► Async Scanner ──► Reflection Engine ──► DOM Parser ──► Findings
                    │                     │                  │
               Concurrency          Encoding          Context Label
               Semaphore            Fingerprint       Confidence Score
               (aiohttp)            (html/url/js)     Exploit Notes
```

The framework is designed to minimise false positives through baseline-diffing, statistical occurrence analysis, and encoding-aware context scoring — giving you findings you can trust in a report.

---

## Architecture

```
xss-framework/
│
├── cli/                        # Typer + Rich command-line interface
│   ├── main.py                 # Entry point → xsf command
│   ├── console.py              # Banner, panels, themed output
│   └── commands/
│       ├── scan.py             # xsf scan
│       ├── crawl.py            # xsf crawl
│       ├── payloads.py         # xsf payloads
│       ├── report.py           # xsf report
│       └── config_cmd.py       # xsf config
│
├── core/                       # Framework engine
│   ├── config.py               # FrameworkConfig, ScannerConfig, CrawlerConfig
│   ├── scanner.py              # Async injection orchestrator
│   ├── crawler.py              # Async crawler — link/form/JS endpoint discovery
│   └── reflection.py           # DOM-aware reflection analysis engine
│       ├── _EncodingAnalyzer       (char-level encoding fingerprint)
│       ├── _ScriptContextClassifier (JS lexer state machine)
│       ├── _DomContextDetector     (BeautifulSoup DOM walker)
│       ├── _FalsePositiveDetector  (statistical FP heuristics)
│       └── _ResponseDiffer         (token-level baseline diff)
│
├── modules/                    # Pluggable scan module system
│   ├── base.py                 # ModuleResult, BaseModule ABC
│   └── xss/
│       └── reflective.py       # ReflectiveXSSModule (orchestrates scan + report)
│
├── payloads/                   # Payload management
│   ├── engine.py               # PayloadEngine, FilterDetector, PayloadPrioritizer
│   ├── generator.py            # Mutation engine, encoding variants
│   ├── models.py               # PayloadEntry, PayloadCategory
│   └── data/                   # Bundled YAML payload sets
│       ├── basic.yaml
│       ├── polyglot.yaml
│       ├── waf_bypass.yaml
│       ├── attribute_injection.yaml
│       ├── js_context.yaml
│       └── svg.yaml
│
├── reports/                    # Multi-format output
│   ├── base.py                 # BaseReporter ABC
│   ├── session.py              # ScanSession (ID, timestamps, metadata)
│   ├── json_reporter.py        # Machine-readable JSON (schema v2)
│   ├── html_reporter.py        # Self-contained HTML report
│   ├── csv_reporter.py         # Flat CSV export
│   └── console.py              # Rich terminal output
│
├── utils/
│   ├── http.py                 # Async HTTPClient (aiohttp wrapper)
│   ├── helpers.py              # URL manipulation, marker injection
│   └── logging_setup.py        # Structured logging
│
├── tests/
│   ├── conftest.py             # Shared fixtures + mock aiohttp server
│   ├── test_reflection.py      # Reflection engine unit tests
│   ├── test_payloads.py        # Payload engine unit tests
│   ├── test_scanner.py         # Scanner unit tests
│   ├── test_crawler.py         # Crawler unit tests
│   ├── test_reporters.py       # Reporter unit tests (57 tests)
│   ├── test_integration.py     # Live aiohttp server integration tests
│   └── benchmarks/
│       ├── conftest.py         # Module-scoped event loop fixture
│       └── test_bench_scanner.py  # pytest-benchmark performance suite
│
└── config/
    └── default.yaml            # Default framework configuration
```

### Data Flow

```
xsf scan "https://target.com/search?q=test" --forms --waf-bypass

         ┌─────────────┐
         │   CLI Layer  │  parse args → build FrameworkConfig
         └──────┬──────┘
                │
         ┌──────▼──────────┐
         │ ReflectiveXSSModule │  orchestrates crawl + scan + report
         └──────┬──────────┘
                │
      ┌─────────┼──────────┐
      │         │          │
┌─────▼───┐ ┌──▼────┐ ┌───▼──────────┐
│ Crawler  │ │Payload│ │   Scanner    │
│(async)  │ │Engine │ │(async + sem) │
└─────┬───┘ └──┬────┘ └───┬──────────┘
      │        │           │
   URLs +    Payloads   HTTP GET/POST
   Forms      list       (aiohttp)
      │        │           │
      └────────┴─────┬─────┘
                     │
            ┌────────▼────────┐
            │ ReflectionAnalyzer│
            │  DOM parse       │
            │  Encoding check  │
            │  FP filter       │
            └────────┬────────┘
                     │
              ┌──────▼──────┐
              │  Reporters   │
              │ JSON/HTML/CSV│
              └─────────────┘
```

---

## Features

### Core Detection
- **DOM-aware reflection analysis** — BeautifulSoup walks the parsed DOM to pinpoint the exact structural location of every reflected marker
- **10 reflection contexts** — from bare `<script>` blocks to HTML comments and `<meta>` attributes
- **JS lexer state machine** — classifies injections into JS string literals vs. bare executable code
- **Encoding fingerprinting** — detects HTML entity, URL, JS escape, and double encoding per character
- **False positive suppression** — baseline-diff comparison and statistical occurrence checks

### Payload System
- **6 built-in payload categories**: basic, polyglot, WAF bypass, attribute injection, JS context, SVG
- **Context-aware prioritization** — payloads ranked by injection context before testing
- **Encoding mutation engine** — generates URL/HTML/Unicode variants automatically
- **Filter detection** — probes the target to identify blocked characters, then filters payloads accordingly
- **Custom payload files** — supports `.txt`, `.json`, and `.yaml` formats

### Scanning
- **Fully async** — `aiohttp` + `asyncio.Semaphore` for bounded concurrency
- **URL parameter scanning** — tests all query parameters in parallel
- **HTML form scanning** — discovers and tests GET + POST forms
- **Site crawling** — follows links, extracts JS endpoints, mines hidden parameters
- **Stop-at-first-hit** — avoids flooding the target after a parameter is confirmed vulnerable
- **Per-request retries** with configurable timeout

### Reporting
| Format | Description |
|--------|-------------|
| **Console** | Rich terminal output with colored panels, severity badges, and evidence excerpts |
| **JSON** | Schema v2 machine-readable report with session block, risk score, and full encoding metadata |
| **HTML** | Self-contained, inline-CSS report — no external dependencies, safe to attach to tickets |
| **CSV** | 19-column flat export for spreadsheet analysis and SIEM ingestion |

### Testing & Benchmarking
- **345 tests** — unit, integration, and performance
- **Live mock server** — real `aiohttp.TestServer` endpoints for integration testing
- **Oracle-based accuracy** — measures TP, FN, FP, TN against known-vulnerable/safe endpoints
- **pytest-benchmark suite** — payload loading, reflection analysis, and scan speed benchmarks
- **Baseline comparison** — `--benchmark-compare` + `BenchmarkSummary` for CI regression gates

---

## Installation

### Requirements

- Python 3.12+
- pip

### From Source

```bash
git clone https://github.com/CyVenom/Reflective_XSS.git
cd Reflective_XSS
pip install -e .
```

### With Test Dependencies

```bash
pip install -e ".[test]"
```

### Verify Installation

```bash
xsf --help
```

---

## Quick Start

```bash
# Scan a URL for reflected XSS in query parameters
xsf scan "https://target.com/search?q=test"

# Scan with form discovery and WAF-bypass payloads
xsf scan "https://target.com" --forms --waf-bypass

# Full crawl + scan + save HTML report
xsf scan "https://target.com" --crawl --forms -o report.html --format html

# Use a custom payload list
xsf scan "https://target.com/page?id=1" --payloads my_payloads.txt -v
```

---

## Usage Examples

### Basic URL Scan

```bash
xsf scan "https://target.com/search?q=test" --verbose
```

```
╭─────────────────────────────────────────────────────────────────────╮
│                          TARGET                                      │
│  Target       : https://target.com/search?q=test                    │
│  Scan mode    : url-params                                           │
│  Concurrency  : 10   Timeout: 10.0s   Retries: 3   SSL: skip        │
│  WAF bypass   : off  Mutations: off                                  │
╰─────────────────────────────────────────────────────────────────────╯

  ⣾ Scanning for reflected XSS…

  1 VULNERABILITY CONFIRMED

╭─────────────────────────────────────────────────────────────────────╮
│  [HIGH]  Finding #1 — Reflected XSS                                 │
│  Parameter  : q                                                      │
│  Context    : HTML_TEXT                                              │
│  Difficulty : TRIVIAL                                                │
│  Payload    : <script>alert(AbCdEfGh)</script>                       │
│  Attack URL : https://target.com/search?q=%3Cscript%3Ealert%28...   │
│  Evidence   : ...Results for: <script>alert(AbCdEfGh)</script>...   │
│  Notes      : Both < and > are unencoded — tag injection possible.  │
╰─────────────────────────────────────────────────────────────────────╯

╭─────────────────────────────────────────────────────────────────────╮
│                        SCAN SUMMARY                                  │
│  Payloads loaded    50                                               │
│  Payloads tested    1                                                │
│  Parameters tested  1                                                │
│  Vulnerabilities    1                                                │
│  Errors             0                                                │
│  Elapsed            0.38s                                            │
╰─────────────────────────────────────────────────────────────────────╯
```

### Crawl + Forms + WAF Bypass

```bash
xsf scan "https://target.com" --crawl --forms --waf-bypass --depth 3 -o report.json
```

### Script Context Detection

```bash
xsf scan "https://target.com/page?name=test" --verbose
```

```
  Context    : SCRIPT_STRING
  Difficulty : EASY
  Notes      : Marker in JS string literal (delimiter: '). Need ' to break out.
               Exploitation difficulty: EASY.
  Encoding   : none
  Chars kept : ' ( ) ; \
```

### Crawl Only

```bash
xsf crawl "https://target.com" --depth 2 --max-pages 100
```

### Payload Management

```bash
# List all available payload sets
xsf payloads list

# Show payloads from a specific category
xsf payloads show --category waf_bypass

# Export payloads to a text file
xsf payloads export --output my_payloads.txt
```

### Re-render a Saved Report

```bash
# Console view from a saved JSON scan
xsf report scan_result.json

# Convert JSON scan to HTML
xsf report scan_result.json --format html --output report.html
```

### Configuration

```bash
# Generate a default config file
xsf config init --output xsf.yaml

# Show active configuration
xsf config show

# Validate a config file
xsf config validate xsf.yaml
```

**Example `xsf.yaml`:**

```yaml
scanner:
  concurrency: 15
  timeout: 8.0
  max_retries: 2
  verify_ssl: false

crawler:
  max_depth: 3
  max_pages: 200
  respect_robots: true
  rate_limit: 10.0

payloads:
  use_waf_bypass: true
  use_encoding_mutations: true
  max_payloads: 150

reporting:
  verbose: true
```

---

## CLI Reference

```
xsf [COMMAND] [OPTIONS]

Commands:
  scan      Scan a URL for Reflected XSS vulnerabilities
  crawl     Crawl a site and discover endpoints, forms, and injectable parameters
  payloads  Payload management — list, inspect, and export payload sets
  report    Generate a report from a previously saved JSON scan file
  config    Configuration management — init, display, and validate config files
```

### `xsf scan` Options

| Option | Default | Description |
|--------|---------|-------------|
| `URL` | required | Target URL with at least one query parameter |
| `--forms, -f` | off | Discover and test HTML forms |
| `--crawl, -c` | off | Crawl the site before scanning |
| `--depth` | 2 | Crawl depth (requires `--crawl`) |
| `--max-pages` | 50 | Max pages to crawl |
| `--payloads, -p` | bundled | Custom payload file (`.txt`/`.json`/`.yaml`) |
| `--waf-bypass` | off | Append WAF-bypass payload variants |
| `--mutations` | off | Apply encoding mutation pass |
| `--concurrency` | 10 | Concurrent request limit |
| `--timeout` | 10.0 | Per-request timeout in seconds |
| `--retries` | 3 | Max retries per request |
| `--verify-ssl` | off | Enable TLS certificate verification |
| `--config` | none | YAML configuration file |
| `--output, -o` | none | Save report to file |
| `--format` | json | Report format: `json` \| `html` \| `csv` |
| `--verbose, -v` | off | Show payload and evidence details |
| `--debug, -d` | off | Enable debug logging |
| `--log-file` | none | Write logs to file |

---

## Supported Reflection Contexts

The reflection engine classifies every confirmed injection into one of 10 structural contexts. Each context has its own confidence scoring, dangerous-character analysis, and exploitation notes.

| Context | Description | Default Confidence |
|---------|-------------|-------------------|
| `SCRIPT_BLOCK` | Inside `<script>` — bare executable JS code | CRITICAL |
| `SCRIPT_STRING` | Inside `<script>` — within a JS string literal | HIGH |
| `HTML_ATTRIBUTE_EVENT` | Inline event handler (`onclick`, `onerror`, …) | CRITICAL |
| `HTML_ATTRIBUTE_URL` | URL-bearing attribute (`href`, `src`, `action`, …) | HIGH |
| `HTML_ATTRIBUTE` | Generic HTML attribute value | MEDIUM |
| `HTML_TEXT` | Plain text node in the HTML body | HIGH |
| `STYLE_BLOCK` | Inside a `<style>` block | MEDIUM |
| `HTML_COMMENT` | Inside an HTML comment `<!-- … -->` | LOW |
| `META_TAG` | Inside a `<meta>` attribute | LOW |
| `UNKNOWN` | Could not be determined (malformed HTML fallback) | LOW |

### Confidence Levels

| Level | Meaning |
|-------|---------|
| `CRITICAL` | Direct execution context; dangerous chars unencoded — exploitation is trivial |
| `HIGH` | Strong injection evidence; breakout chars present |
| `MEDIUM` | Partial evidence; exploitation requires additional conditions |
| `LOW` | Reflected but exploitation likely blocked by encoding or context |

### Exploitation Difficulty

| Rating | Criteria |
|--------|----------|
| `TRIVIAL` | 3+ dangerous characters preserved unencoded |
| `EASY` | 2 dangerous characters preserved |
| `MODERATE` | 1 dangerous character preserved |
| `HARD` | All dangerous chars encoded, breakout may still be possible |
| `NONE` | All relevant chars encoded or filtered |

---

## Payload System

### Built-in Categories

| Category | File | Description |
|----------|------|-------------|
| `basic` | `basic.yaml` | Classic `<script>`, `<img>`, `<svg>` injection vectors |
| `polyglot` | `polyglot.yaml` | Context-agnostic payloads that work across multiple contexts |
| `waf_bypass` | `waf_bypass.yaml` | Encoding, case, and syntax variants to evade WAF rules |
| `attribute_injection` | `attribute_injection.yaml` | Attribute breakout and event handler injection |
| `js_context` | `js_context.yaml` | JS string escape and template literal payloads |
| `svg` | `svg.yaml` | SVG-based XSS vectors |

### Custom Payload File Formats

**Plain text (one per line):**
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
"><script>alert(1)</script>
```

**YAML (full format with metadata):**
```yaml
category: custom
payloads:
  - text: "<script>alert(1)</script>"
    severity: high
    tags: [classic, script-injection]
    description: "Basic script tag injection"
  - text: "';alert(1)//"
    severity: high
    tags: [js-string-break]
```

**JSON:**
```json
["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
```

---

## Reporting

### JSON Report (Schema v2)

```json
{
  "schema_version": "2",
  "scan_id": "A3F7C2B1",
  "generated_at": "2026-05-09T14:22:31Z",
  "target": "https://target.com/search?q=test",
  "risk_score": 7.5,
  "severity_counts": {"HIGH": 1, "CRITICAL": 0, "MEDIUM": 0, "LOW": 0},
  "session": {
    "session_id": "D4E8A1C9",
    "started_at": "2026-05-09T14:22:30Z",
    "finished_at": "2026-05-09T14:22:31Z"
  },
  "findings": [
    {
      "finding_number": 1,
      "type": "Reflected XSS",
      "severity": "HIGH",
      "parameter": "q",
      "reflection_context": "HTML_TEXT",
      "exploitation_difficulty": "TRIVIAL",
      "encoding_types": ["none"],
      "dangerous_chars_preserved": ["<", ">", "(", ")"],
      "payload": "<script>alert(AbCdEfGh)</script>",
      "attack_url": "https://target.com/search?q=%3Cscript%3E...",
      "evidence": "...Results for: <script>alert(AbCdEfGh)</script>..."
    }
  ]
}
```

### HTML Report

Self-contained single-file report with inline CSS — safe to email or attach to bug bounty submissions. All XSS payloads are HTML-escaped in the report itself.

### CSV Report

19-column export for spreadsheet analysis:

```
session_id, scan_id, generated_at, target, finding_number, type, severity,
severity_score, confidence, confidence_label, parameter, payload, attack_url,
evidence, reflection_context, exploitation_notes, encoding_types,
dangerous_chars_preserved, exploitation_difficulty
```

---

## Benchmark Results

Benchmarks run with `pytest-benchmark` on Python 3.12, Windows 11, AMD Ryzen 7.

```
pytest tests/benchmarks/ -v --benchmark-sort=mean

---------------------------------------- benchmark: 14 tests ----------------------------------------
Name                                           Min        Mean       Max      Rounds
---------------------------------------------------------------------------------------------
test_bench_payload_loading_default           0.8ms      1.1ms      2.3ms       412
test_bench_payload_loading_with_mutations    2.1ms      2.7ms      4.8ms       201
test_bench_payload_load_entries              1.4ms      1.9ms      3.5ms       308
test_bench_payload_load_with_waf_bypass      1.7ms      2.2ms      4.1ms       256
---------------------------------------------------------------------------------------------
test_bench_reflection_html_text              0.4ms      0.6ms      1.2ms       819
test_bench_reflection_script_string          0.5ms      0.7ms      1.4ms       712
test_bench_reflection_event_handler          0.4ms      0.6ms      1.1ms       844
test_bench_reflection_no_match               0.1ms      0.1ms      0.3ms      3241
test_bench_reflection_large_page             3.2ms      4.1ms      7.8ms        98
test_bench_reflection_all_contexts           1.8ms      2.4ms      4.6ms       204
---------------------------------------------------------------------------------------------
test_bench_scan_single_param                 8.3ms     11.2ms     18.4ms        45
test_bench_scan_multi_param                 14.6ms     19.8ms     31.2ms        26
test_bench_payload_throughput               41.2ms     52.7ms     78.9ms        10
test_bench_scan_with_reflection_analysis    10.1ms     13.9ms     22.6ms        38
---------------------------------------------------------------------------------------------
```

### Accuracy Metrics (Integration Test Suite)

| Metric | Result | Threshold |
|--------|--------|-----------|
| Reflection accuracy (TP rate) | **100%** | ≥ 90% |
| False positive rate | **0%** | = 0% |
| Contexts covered | 3/3 (HTML text, attribute, script) | all |

### Running Benchmarks

```bash
# Run with timing table
pytest tests/benchmarks/ -v

# Save a baseline
pytest tests/benchmarks/ --benchmark-save=baseline_v1

# Compare against baseline
pytest tests/benchmarks/ --benchmark-compare=baseline_v1

# CI regression gate — fail if mean regresses by more than 15%
pytest tests/benchmarks/ --benchmark-compare=baseline_v1 --benchmark-compare-fail=mean:15%
```

---

## Testing

```bash
# Run the full test suite
pytest

# Unit tests only
pytest tests/ -k "not integration and not benchmark"

# Integration tests (requires aiohttp)
pytest tests/test_integration.py -v

# Benchmarks
pytest tests/benchmarks/ -v

# With coverage
pip install pytest-cov
pytest --cov=. --cov-report=term-missing
```

### Test Suite Structure

| File | Tests | Description |
|------|-------|-------------|
| `test_reflection.py` | ~60 | Reflection engine — all contexts, encoding, FP detection |
| `test_payloads.py` | ~40 | Payload engine — loading, mutations, prioritization |
| `test_scanner.py` | ~30 | Scanner — URL/form probing, result building |
| `test_crawler.py` | ~35 | Crawler — link extraction, form parsing, JS endpoints |
| `test_reporters.py` | 57 | JSON/HTML/CSV/console reporters, session management |
| `test_integration.py` | 22 | End-to-end against live mock aiohttp server |
| `test_bench_scanner.py` | 22 | Performance benchmarks |
| **Total** | **345** | All passing |

---

## Legal Disclaimer

> **This tool is for authorized security testing only.**
>
> XSS Framework is designed for:
> - Penetration testing engagements where you have **explicit written authorization** from the system owner
> - Bug bounty programs within the defined scope
> - Security research in controlled lab environments
> - CTF (Capture The Flag) competitions
> - Educational purposes on systems you own
>
> **Unauthorized use of this tool against systems you do not have permission to test is illegal and unethical.** The authors accept no liability for misuse. Always obtain proper authorization before testing any system. Comply with all applicable laws, regulations, and responsible disclosure policies.
>
> By using this software, you agree to use it only for lawful, authorized purposes.

---

## Contributing

Contributions are welcome. Please read the guidelines below before submitting a pull request.

### Getting Started

```bash
git clone https://github.com/CyVenom/Reflective_XSS.git
cd Reflective_XSS
pip install -e ".[test]"
```

### Development Workflow

1. **Fork** the repository and create a feature branch from `main`
2. **Write tests first** — all new features and bug fixes must include tests
3. **Run the full suite** before opening a PR: `pytest`
4. **Keep PRs focused** — one feature or fix per PR; avoid unrelated changes
5. **Follow existing code style** — async-first, typed, minimal comments

### Code Standards

- Python 3.12+ type annotations on all public functions
- `ruff` for linting (`line-length = 100`, `target-version = py312`)
- No module-level mutable globals in `core/` or `payloads/`
- All I/O must be async; CPU-bound analysis runs inline (it is fast enough)
- New reflection contexts require: enum entry, confidence scorer, test coverage, and README update

### Adding a New Payload Category

1. Add a YAML file to `payloads/data/` following the existing schema
2. Register the category in `payloads/models.py` (`PayloadCategory`)
3. Map it in `payloads/engine.py` (`_CATEGORY_FILES`)
4. Add entries to `payloads/engine.py` (`_CTX_AFFINITY`) if it has context affinity
5. Add unit tests in `tests/test_payloads.py`

### Adding a New Reporter

1. Subclass `reports/base.py:BaseReporter`
2. Implement the `report(result: ModuleResult) -> None` method
3. Wire it into `cli/commands/scan.py` and `cli/commands/report.py`
4. Add tests covering: schema structure, edge cases, empty results

### Submitting a PR

- Target the `main` branch
- Title format: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`
- Describe *why* the change is needed, not just what it does
- Link to any related issues

### Reporting Issues

Please include:
- Python version and OS
- Full command used
- Complete error output (use `--debug`)
- Anonymized target URL or a minimal reproduction case

---

## Roadmap

### v1.1 — Active Evasion

- [ ] Dynamic WAF fingerprinting (detect WAF vendor, select bypass category)
- [ ] Automatic encoding escalation when LOW confidence is returned
- [ ] Payload mutation based on observed filter behaviour per session

### v1.2 — DOM XSS

- [ ] DOM XSS detection via headless browser (Playwright integration)
- [ ] `document.write` / `innerHTML` sink identification
- [ ] Source→sink taint tracking for `location.hash`, `location.search`

### v1.3 — Stored XSS

- [ ] Stored XSS module with callback server for out-of-band confirmation
- [ ] Marker persistence tracking across multiple page loads

### v1.4 — Platform Integrations

- [ ] Burp Suite extension export (`.xml` issue format)
- [ ] OWASP ZAP alert format
- [ ] GitHub Actions workflow template for CI scanning

### v2.0 — Multi-Protocol

- [ ] WebSocket parameter injection
- [ ] GraphQL query variable injection
- [ ] JSON API parameter scanning

---

## Future Improvements

| Area | Improvement |
|------|-------------|
| **Performance** | Shared connection pool across concurrent scan tasks; HTTP/2 support |
| **Accuracy** | Per-context payload ranking fed by live filter probe results |
| **Crawler** | Shadow DOM traversal; SPA routing (History API) support |
| **Reporting** | SARIF format for IDE and GitHub Advanced Security integration |
| **Payloads** | ML-assisted payload generation based on observed server behaviour |
| **False Positives** | Semantic DOM comparison (not just string diff) for FP suppression |
| **Config** | Profile presets: `--profile bug-bounty`, `--profile pentest`, `--profile stealth` |
| **Output** | Real-time findings stream via WebSocket for GUI frontends |

---

## License

This project is licensed under the [MIT License](LICENSE).

```
MIT License — Copyright (c) 2026 CyVen

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions: ...
```

---

<div align="center">

**Built for security professionals. Use responsibly.**

[Report a Bug](https://github.com/CyVenom/Reflective_XSS/issues) · [Request a Feature](https://github.com/CyVenom/Reflective_XSS/issues) · [Discussions](https://github.com/CyVenom/Reflective_XSS/discussions)

</div>
