<h1 align="center">
  <br>
  <pre>
   ██████╗ ███████╗ ██████╗ █████╗ ██████╗
  ██╔═══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗
  ██║   ██║███████╗██║     ███████║██████╔╝
  ██║   ██║╚════██║██║     ██╔══██║██╔══██╗
  ╚██████╔╝███████║╚██████╗██║  ██║██║  ██║
   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝</pre>
  <b>OSCAR</b>
</h1>

<h4 align="center">Omni-Signal Capture &amp; Agentic Recon — v2.0.0</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go-00ADD8?logo=go&logoColor=white">
  <img src="https://img.shields.io/badge/Version-2.0.0-blueviolet">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-informational">
  <img src="https://img.shields.io/badge/Pipeline-5%20Stages-success">
  <img src="https://img.shields.io/badge/AI-Ollama%20%28Free%2C%20Local%29-orange">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey">
</p>

<p align="center">
  <b>Production-grade bug bounty recon in a single binary.</b><br>
  5-stage concurrent pipeline · resumable scans · live UI · local AI triage · no API keys
</p>

---

## What is OSCAR?

OSCAR is a single-binary CLI that orchestrates **15+ security tools** across a fully concurrent 5-stage reconnaissance pipeline. Drop it on any machine, run `oscar -up` to install dependencies, then `oscar -t target.com` to get a full recon report — subdomains, live services, ports, crawled URLs, vulnerabilities, and secrets — with an AI-powered triage summary, all from one command.

Key design principles:
- **Speed** — modules within each stage run in parallel; `-fast` mode skips the slowest tools for a ~3× speedup
- **Resilience** — state is saved after every module; `--resume` skips already-completed work
- **Zero friction** — one binary, one install command, no API keys, no config files required
- **Visibility** — live terminal UI with per-module spinners, real-time counters, and elapsed timers

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Scan Modes](#scan-modes)
5. [All Flags](#all-flags)
6. [Pipeline Stages](#pipeline-stages)
7. [Live UI](#live-ui)
8. [Reports](#reports)
9. [AI Triage](#ai-triage)
10. [MCP / Agentic Setup](#mcp--agentic-setup)
11. [Output Structure](#output-structure)
12. [Examples](#examples)
13. [Troubleshooting](#troubleshooting)
14. [Requirements](#requirements)

---

## Prerequisites

Before installing OSCAR, make sure you have:

| Requirement | Version | Install |
|---|---|---|
| **Go** | 1.21+ | [go.dev/dl](https://go.dev/dl/) |
| **Git** | any | `apt install git` / `brew install git` |
| **Ollama** *(optional)* | latest | [ollama.com](https://ollama.com) — only needed for AI triage |

**Check Go is installed:**
```bash
go version
# should print: go version go1.21.x ...
```

**Check your PATH includes Go binaries:**
```bash
echo $PATH | grep -o "$HOME/go/bin"
# if nothing prints, add this to your ~/.bashrc or ~/.zshrc:
export PATH="$PATH:$HOME/go/bin"
```

---

## Installation

### Option 1 — Install from source (recommended)

**Step 1 — Install the OSCAR binary**
```bash
go install -v github.com/su6osec/oscar@latest
```

**Step 2 — Install all 30+ tools, wordlists, and the AI model for your hardware**
```bash
oscar -up
```

That's it. `oscar -up` automatically installs:
- All recon tools (subfinder, dnsx, alterx, naabu, httpx, tlsx, katana, gau, getJS, ffuf, nuclei, dalfox, assetfinder)
- SecLists wordlists (cloned to `~/SecLists`)
- The best Ollama AI model for your system RAM

### Option 2 — Build from source

```bash
# Clone the repo
git clone https://github.com/su6osec/oscar.git
cd oscar

# Build the binary
go build -o oscar .

# Move it to your PATH (optional)
sudo mv oscar /usr/local/bin/

# Install dependencies
oscar -up
```

### Option 3 — Kali Linux / Parrot OS (apt tools available)

```bash
# Install Go first if needed
apt install golang-go

# Then install oscar
go install -v github.com/su6osec/oscar@latest

# Install remaining tools
oscar -up
```

### Verify installation

```bash
oscar -v
# OSCAR v2.0.0
```

---

## Quick Start

```bash
# Full scan with all defaults
oscar -t target.com

# Fast mode — skip slow tools, ~3× faster
oscar -t target.com -fast

# Save report as PDF
oscar -t target.com -f pdf

# More threads, longer timeout for large targets
oscar -t target.com -threads 100 -timeout 45

# Resume a previous scan (skip completed stages)
oscar -t target.com -resume

# Skip AI triage
oscar -t target.com -no-ai

# Start from stage 3 (skip passive discovery and DNS)
oscar -t target.com -stage 3
```

---

## Scan Modes

OSCAR has three modes that trade thoroughness for speed:

### ⚡ Fast Mode (`-fast`)
Skips the three slowest optional tools: **alterx** (DNS permutations), **ffuf** (directory brute-force), and **dalfox** (XSS scanning).

On a large target this reduces scan time from **90+ minutes to ~25 minutes** without missing the most critical findings.

```bash
oscar -t target.com -fast
```

Best for: quick triage, CI/CD pipelines, time-limited engagements.

### ● Standard Mode (default)
Runs all tools except deep permutation modes. GAU fetches historical URLs for the root domain only.

```bash
oscar -t target.com
```

Best for: most bug bounty programs.

### ◎ Deep Mode (`-deep`)
Enables everything including GAU's `--subs` flag (fetches historical URLs for all discovered subdomains). Can take several hours on large targets.

```bash
oscar -t target.com -deep
```

Best for: thorough engagements, large scope programs, when time is not a constraint.

---

## All Flags

```
Scanning:
  -t <domain>    Target domain (required)                e.g. target.com
  -threads <n>   Concurrent threads per module           [default: 50]
  -timeout <n>   Per-module timeout in minutes           [default: 30]
  -stage <n>     Start from a specific stage (1–5)       [default: 1]
  -resume        Resume a previous scan (skip completed modules)
  -fast          Skip alterx / ffuf / dalfox  (~3× faster)
  -deep          Enable all tools + gau --subs (slow, thorough)

Output:
  -f <format>    Report format: txt, md, json, csv, pdf  [default: md]
  -no-ai         Skip Ollama AI triage

System:
  -up            Install / update all required tools
  -agent         MCP / agentic setup for Claude, Cursor, Windsurf, etc.
  -v             Show version and exit
```

---

## Pipeline Stages

OSCAR runs 5 stages in order. Modules **within** each stage run in **parallel** for maximum throughput.

```
Stage 1 ── Passive Discovery  (parallel)
           subfinder · assetfinder · crt.sh (built-in)
           └─► merges into raw_subdomains.txt

Stage 2 ── DNS Resolution  (sequential)
           dnsx ──► alive_hosts.txt
           alterx  [standard/deep only] ──► adds permutation hosts

Stage 3 ── Service Mapping  (parallel)
           naabu   ──► open_ports.txt
           httpx   ──► live_web.txt
           tlsx    ──► tls_info.txt

Stage 4 ── Content Discovery  (parallel)
           gau     ──► historical_urls.txt
           katana  ──► crawled_urls.txt
           getJS   ──► js_files.txt
           ffuf    [standard/deep only] ──► directories.txt
           └─► merges into all_urls.txt

Stage 5 ── Vulnerability Analysis  (parallel)
           nuclei     ──► nuclei_hits.txt
           nuclei-js  ──► js_secrets.txt
           dalfox     [standard/deep only] ──► xss_hits.txt
```

**Stage dependencies:** each stage reads the output files from the previous stage. Using `-stage N` bootstraps with the target domain if prior stage files don't exist.

---

## Live UI

OSCAR v2.0 features a fully animated terminal interface:

```
  ▶  Stage 1/5  ·  Passive Discovery  (parallel)
  ────────────────────────────────────────────────────
  ⠙ Subfinder          → 1.2K found   [0:08]
  ⠹ Assetfinder        → 813 found    [0:08]
  ✔ Crt.sh             → 47           [0:03]

  ▶  Stage 2/5  ·  DNS Resolution  (sequential)
  ────────────────────────────────────────────────────
  ⠸ Dnsx               → 342 found    [0:21]
```

**What you see while a module runs:**
- **Braille spinner** (`⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏`) animates at 80ms intervals
- **Live counter** updates in real-time as each tool outputs results
- **Elapsed timer** counts up so you can estimate remaining time

**When a module finishes:**
- `✔ Subfinder    → 2.1K  [0:48]` — green, with final count and elapsed time
- `✘ Dalfox       context canceled` — red, if it failed

**Summary table after all stages complete:**
```
┌────────────────────────────────────────────────┐
│ Category            │ Found  │ Status          │
│  Subdomains (raw)   │ 2.1K   │ ████████████    │
│  Alive Hosts        │ 625    │ █████████░░░    │
│  Web Services       │ 385    │ ████████████    │
│  Vulnerabilities    │ 3      │ ▲ REVIEW        │
│  Secrets Found      │ 0      │ ● NONE          │
└────────────────────────────────────────────────┘
  Reports → reports/target.com   [total: 28m14s]
```

---

## Reports

OSCAR generates a report automatically after each scan. Choose the format with `-f`:

| Format | Flag | Description |
|--------|------|-------------|
| Markdown | `-f md` | Default. Human-readable with sections and tables |
| Plain text | `-f txt` | Clean text, no markup |
| JSON | `-f json` | Structured data for scripting / integrations |
| CSV | `-f csv` | Spreadsheet-compatible |
| PDF | `-f pdf` | Professional report via gofpdf |

Reports are saved to `reports/<target>/<target>_oscar_report.<ext>`.

**If Ollama is running**, an AI triage section is automatically appended to the report with:
- Executive summary (2–3 sentences)
- Top 3 most critical findings with reasoning
- Specific attack vectors and follow-up actions
- Quick wins (easy-to-confirm vulnerabilities)

---

## AI Triage

OSCAR uses a **local Ollama model** — no API keys, no data leaves your machine.

### Setup

```bash
# Install Ollama (one-time)
curl -fsSL https://ollama.com/install.sh | sh

# Start the Ollama daemon
ollama serve

# oscar -up will pull the right model for your RAM automatically
oscar -up
```

### Model selection by RAM

| System RAM | Model selected |
|---|---|
| < 4 GB | `qwen2.5:0.5b` (ultra-light) |
| 4–8 GB | `phi3.5` (fast, capable) |
| 8–16 GB | `llama3.2:3b` (balanced) |
| ≥ 16 GB | `llama3.1:8b` (full quality) |

`oscar -up` detects your RAM automatically and only downloads the appropriate model. If it's already installed, the download is skipped.

### Skip AI triage

```bash
oscar -t target.com -no-ai
```

If Ollama is not running, OSCAR prints a warning and continues — the AI step is always optional.

---

## MCP / Agentic Setup

OSCAR can serve as an **MCP (Model Context Protocol) server**, letting AI tools like Claude, Cursor, and Windsurf call it directly.

```bash
oscar -agent
```

This command:
1. Detects which AI tools you have installed (Claude Desktop, Cursor, Windsurf, VS Code with Continue, Zed)
2. Uses local AI (if available) to explain what MCP is and what will be changed
3. Asks for per-file `[y/N]` consent before patching any config file
4. Adds the OSCAR MCP entry to approved config files

**Manual setup** — add this to your AI tool's MCP config:

```json
{
  "mcpServers": {
    "oscar": {
      "command": "/path/to/oscar",
      "args": ["-mcp"]
    }
  }
}
```

Replace `/path/to/oscar` with the output of `which oscar`.

---

## Output Structure

```
reports/
└── <target>/
    ├── recon/
    │   ├── subfinder_out.txt       raw subfinder results
    │   ├── assetfinder_out.txt     raw assetfinder results
    │   ├── crtsh_out.txt           crt.sh certificate transparency
    │   ├── subdomains_raw.txt      merged + deduped subdomains
    │   ├── subdomains_alive.txt    DNS-confirmed live hosts
    │   ├── live_web.txt            httpx results (URL + title + tech + status)
    │   ├── open_ports.txt          naabu port scan results
    │   └── tls_info.txt            tlsx certificate info
    ├── content/
    │   ├── historical_urls.txt     GAU historical URLs
    │   ├── crawled_urls.txt        katana crawl results
    │   ├── all_urls.txt            merged + deduped URL list
    │   ├── js_files.txt            discovered JavaScript files
    │   └── directories.txt         ffuf directory brute-force results
    ├── vulns/
    │   ├── nuclei_hits.txt         nuclei template matches
    │   ├── js_secrets.txt          nuclei secrets scan on JS files
    │   └── xss_hits.txt            dalfox XSS findings
    ├── .scan_state.json            per-module completion state (for -resume)
    └── <target>_oscar_report.md    final report
```

---

## Examples

### Basic full scan

```bash
oscar -t target.com
```

### Fast scan, PDF report

```bash
oscar -t target.com -fast -f pdf
```

### High-thread scan for large targets

```bash
oscar -t target.com -threads 100 -timeout 60
```

### Resume an interrupted scan

```bash
# First run was interrupted
oscar -t target.com -threads 80

# Resume from where it left off
oscar -t target.com -threads 80 -resume
```

### Skip AI, get JSON output for scripting

```bash
oscar -t target.com -no-ai -f json
cat reports/target.com/target.com_oscar_report.json | jq '.stats'
```

### Start from stage 3 (already have subdomains)

```bash
# You already ran stages 1+2 before
oscar -t target.com -stage 3
```

### Deep scan over the weekend

```bash
oscar -t target.com -deep -threads 50 -timeout 60 -f pdf
```

---

## Troubleshooting

### `oscar: command not found` after `go install`

Your Go bin directory is not in your PATH. Fix:

```bash
echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc   # or ~/.bashrc
source ~/.zshrc
```

### Tool not found errors (e.g. `subfinder not found`)

Run the installer:

```bash
oscar -up
```

If a specific tool still fails, install it manually:

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hahwul/dalfox/v2@latest
```

### Scans taking too long

Use `-fast` to skip the slowest tools:

```bash
oscar -t target.com -fast
```

Or increase threads and reduce timeout:

```bash
oscar -t target.com -threads 100 -timeout 15
```

### AI triage skipped / "Ollama not running"

Start the Ollama daemon:

```bash
ollama serve
```

Or skip AI entirely with `-no-ai`.

### Stage 3+ returns 0 results when using `-stage N`

This is expected when prior stage output files don't exist. OSCAR bootstraps with the target domain so tools can still run. Run from stage 1 for best results, or use `-resume` to pick up where you left off.

### Interrupted scan loses progress

OSCAR saves state after every module. Run with `-resume` to continue:

```bash
oscar -t target.com -resume
```

---

## Requirements

| Component | Requirement |
|---|---|
| Go | 1.21 or later |
| OS | Linux, macOS, Windows (Linux recommended) |
| Disk | ~2 GB (SecLists wordlists) |
| RAM | 2 GB minimum; 8 GB+ recommended for AI triage |
| Network | Required for tool installation and scanning |
| Ollama | Optional — only needed for AI triage |

---

## Architecture

Ten source files, all `package main`:

| File | Responsibility |
|------|---------------|
| `main.go` | CLI flags, entry point, signal handling, ASCII banner |
| `types.go` | Shared types: `Config`, `Finding`, `ScanStats` |
| `state.go` | State persistence (`ScanState`) — JSON file for resume support |
| `workspace.go` | Directory layout, file path constants, `MergeDedup`, `CountLines` |
| `engine.go` | Stage-based pipeline orchestrator; parallel execution via goroutines |
| `ui.go` | Live terminal UI — `StageUI` with pterm.Area renderer, spinners, counters |
| `modules.go` | All 15 module wrappers + `buildPipeline()` — defines the 5-stage DAG |
| `install.go` | Auto-installer for all tools, SecLists, Ollama model setup |
| `ai.go` | Ollama REST client, RAM-based model selection, AI triage |
| `report.go` | Multi-format report generation: txt, md, json, csv, pdf |
| `db.go` | SQLite schema (scans, subdomains, services, urls, vulnerabilities) |

---

## License

MIT © [su6osec](https://github.com/su6osec/oscar)

---

<p align="center">
  Built for bug bounty hunters · <a href="https://github.com/su6osec/oscar/issues">Report an issue</a>
</p>
