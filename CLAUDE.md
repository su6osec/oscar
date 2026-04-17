# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What is OSCAR

OSCAR (Omni-Signal Capture & Agentic Recon) v2.0 is a production-grade, single-binary bug bounty reconnaissance CLI written in Go. It orchestrates 15+ external security tools across a 5-stage concurrent pipeline, persists state for resumable runs, generates multi-format reports, and offers AI-powered triage via local Ollama models (100% free, no API keys).

## Commands

```bash
# Build
go build -o oscar .

# Install from source
go install -v github.com/su6osec/oscar@latest

# Install / update all 30+ dependency tools
./oscar -up

# Run a full scan
./oscar -t example.com
./oscar -t example.com -f pdf               # report format: txt, md, json, csv, pdf
./oscar -t example.com -threads 50 -timeout 30
./oscar -t example.com -resume              # resume a previous scan
./oscar -t example.com -stage 3             # start from stage 3
./oscar -t example.com -no-ai              # skip Ollama AI triage

# MCP config for Claude/Cursor
./oscar -mcp

# Version
./oscar -v
```

No test suite exists. There is no linter configuration.

## Architecture

Ten source files, all in `package main`:

| File | Responsibility |
|------|---------------|
| `main.go` | CLI flags, entry point (`RunScan`), signal handling, ASCII banner |
| `types.go` | Shared types: `Config`, `Finding`, `ScanStats` |
| `state.go` | State persistence (`ScanState`) — JSON file per scan for resume support |
| `workspace.go` | Directory layout, file path constants, helpers (`MergeDedup`, `CountLines`, `FindTool`) |
| `engine.go` | Stage-based pipeline orchestrator; parallel module execution via goroutines + `sync.WaitGroup` |
| `modules.go` | All 15 module wrappers + `buildPipeline()` — defines the 5-stage DAG |
| `install.go` | Auto-installer for all tools, SecLists cloning, Ollama model setup |
| `ai.go` | Ollama REST client, RAM-based model selection (`SelectAIModel`), AI triage (`AITriage`) |
| `report.go` | Multi-format report generation: txt, md, json, csv, pdf (via gofpdf) |
| `db.go` | SQLite schema (5 tables: scans, subdomains, services, urls, vulnerabilities) |

### Pipeline stages

| Stage | Mode | Modules |
|-------|------|---------|
| 1 Passive Discovery | parallel | subfinder, assetfinder, crt.sh (built-in HTTP) |
| 2 DNS Resolution | sequential | dnsx, alterx |
| 3 Service Mapping | parallel | naabu, httpx, tlsx |
| 4 Content Discovery | parallel | gau, katana, getJS, ffuf |
| 5 Vuln Analysis | parallel | nuclei, nuclei-js, dalfox |

Stage 1 modules all append to `raw_subdomains.txt` via `PostRun` merge+dedup. Stage transitions depend on the previous stage's output files (checked via `FileExists`).

### Workspace layout

```
reports/<target>/
├── recon/          subdomains, DNS, ports, live web
├── content/        URLs, JS files, directories
├── vulns/          nuclei hits, XSS, secrets
├── javascript/     JS files (populated by getJS/katana)
├── logs/           module logs
└── .scan_state.json  per-module completion state
```

### Key patterns

- **`runCmd`** (`modules.go`) — generic subprocess runner that streams stdout to an output file and returns line count. All external tool wrappers call this.
- **`withTimeout`** — wraps context with per-module timeout (minutes, from `cfg.Timeout`).
- **`MergeDedup`** — used in PostRun hooks to consolidate parallel outputs before the next stage reads them.
- **AI model selection** — `SelectAIModel()` in `ai.go` maps total system RAM to Ollama model: `<4GB→qwen2.5:0.5b`, `<8GB→phi3.5:mini`, `<16GB→llama3.2:3b`, `≥16GB→llama3.1:8b`.
- **Resume** — `ScanState.IsDone(id)` is checked in `engine.runModule` before executing; module state is written to `.scan_state.json` after each completion.

## Key dependencies

| Package | Purpose |
|---------|---------|
| `pterm` | Spinners, section headers, progress tables, colored output |
| `jung-kurt/gofpdf` | PDF report generation |
| `modernc.org/sqlite` | Embedded SQLite (CGO-free, pure Go) |
| `pbnjay/memory` | System RAM detection for AI model selection |
