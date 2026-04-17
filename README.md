<h1 align="center">OSCAR</h1>

<h4 align="center">Omni-Signal Capture & Agentic Recon — v2.0</h4>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Go-00ADD8.svg">
  <img src="https://img.shields.io/badge/Version-2.0.0-blueviolet.svg">
  <img src="https://img.shields.io/badge/Pipeline-5 Stages-success.svg">
  <img src="https://img.shields.io/badge/AI-Ollama%20(Free%2C%20Local)-orange.svg">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey.svg">
</p>

---

OSCAR is a production-grade, single-binary bug bounty reconnaissance CLI written in Go. It orchestrates 15+ external security tools across a **5-stage concurrent pipeline**, persists state for resumable runs, generates multi-format reports, and offers AI-powered triage via local [Ollama](https://ollama.com) models — **100% free, no API keys required**.

```
   ██████╗ ███████╗ ██████╗ █████╗ ██████╗
  ██╔═══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗
  ██║   ██║███████╗██║     ███████║██████╔╝
  ██║   ██║╚════██║██║     ██╔══██║██╔══██╗
  ╚██████╔╝███████║╚██████╗██║  ██║██║  ██║
   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝
  Omni-Signal Capture & Agentic Recon  v2.0
```

---

## Installation

**Step 1 — Install OSCAR**

```bash
go install -v github.com/su6osec/oscar@latest
```

**Step 2 — Install all required tools (30+), wordlists, and AI model**

```bash
oscar -up
```

> `oscar -up` installs subfinder, dnsx, naabu, httpx, katana, nuclei, dalfox, SecLists, and pulls the optimal Ollama model for your hardware automatically.

---

## Quick Start

```bash
oscar -t tesla.com
```

```bash
oscar -t tesla.com -f pdf
```

```bash
oscar -t tesla.com -threads 100 -timeout 45
```

```bash
oscar -t tesla.com -resume
```

```bash
oscar -t tesla.com -stage 3
```

```bash
oscar -t tesla.com -no-ai
```

---

## Pipeline

OSCAR runs 5 stages in sequence. Modules **within** each stage run in parallel.

| Stage | Mode | Tools |
|-------|------|-------|
| 1 — Passive Discovery | parallel | subfinder, assetfinder, crt.sh (built-in) |
| 2 — DNS Resolution | sequential | dnsx, alterx |
| 3 — Service Mapping | parallel | naabu, httpx, tlsx |
| 4 — Content Discovery | parallel | gau, katana, getJS, ffuf |
| 5 — Vuln Analysis | parallel | nuclei, nuclei-js, dalfox |

**Output workspace:**
```
reports/<target>/
├── recon/       subdomains, alive hosts, ports, live web
├── content/     URLs, JS files, directories
├── vulns/       nuclei hits, XSS, secrets
└── .scan_state.json
```

---

## Features

- **Concurrent pipeline** — stages run in order; modules within each stage run in parallel for maximum speed
- **Resume support** — state is saved after each module; re-run with `-resume` to skip completed stages
- **Built-in crt.sh** — no extra tool needed for certificate transparency lookups
- **AI triage** — local Ollama AI analyzes top findings and appends a prioritized summary to your report
- **Smart model selection** — `oscar -up` detects your system RAM and pulls the best-fitting model automatically (no overloading small machines)
- **Multi-format reports** — `txt`, `md`, `json`, `csv`, `pdf`
- **Dual Ctrl+C** — first interrupt stops the current module gracefully; second interrupt force-exits
- **MCP integration** — `oscar -agent` auto-detects installed AI tools (Claude Desktop, Cursor, Windsurf) and patches their config files

---

## AI Model Selection

OSCAR selects the best local Ollama model based on your system RAM:

| RAM | Model |
|-----|-------|
| < 4 GB | `qwen2.5:0.5b` |
| 4–8 GB | `phi3.5:mini` |
| 8–16 GB | `llama3.2:3b` |
| ≥ 16 GB | `llama3.1:8b` |

If the appropriate model is already installed, `oscar -up` skips the download.

---

## Agentic MCP Setup

```bash
oscar -agent
```

This command:
1. Shows your OSCAR binary path
2. Prints the JSON block to add to your AI tool
3. Scans for installed AI tools (Claude Desktop, Cursor, Windsurf, VS Code, Zed)
4. **Auto-patches** any detected config files that don't already have the OSCAR MCP entry
5. Prompts you to restart your AI app

---

## Flags

```
-t <domain>    Target domain
-f <format>    Report format: txt, md, json, csv, pdf  [default: md]
-threads <n>   Concurrent threads per module           [default: 50]
-timeout <n>   Per-module timeout in minutes           [default: 30]
-stage <n>     Start from stage 1–5                    [default: 1]
-resume        Resume a previous scan
-no-ai         Skip Ollama AI triage
-up            Install / update all tools
-agent         MCP setup for Claude, Cursor, Windsurf, etc.
-v             Show version
```

---

## Requirements

- Go 1.21+
- Linux, macOS, or Windows
- Internet connection for tool installation
- [Ollama](https://ollama.com) (optional, for AI triage)

---

## License

MIT © [su6osec](https://github.com/su6osec)
