# ⚡ OSCAR v1.0.0-ULTRA ⚡
### Open-Source Cyber Attack Reconnaissance & Mega-Pipeline

[![Go Report Card](https://goreportcard.com/badge/github.com/su6osec/oscar)](https://goreportcard.com/report/github.com/su6osec/oscar)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Version](https://img.shields.io/badge/Version-1.0.0--ULTRA-blueviolet)]()

OSCAR is an advanced, orchestrated reconnaissance engine designed for elite bug bounty hunters and red teamers. It mathematically maps target architectures, serializes HTTP responses, and executes zero-day payloads through a high-performance mega-pipeline.

---

## 🚀 Key Features

- **Mega-Pipeline Architecture:** Seamlessly chains `Subfinder` ➝ `Dnsx` ➝ `Naabu` ➝ `Httpx` ➝ `GAU` ➝ `Katana` ➝ `Nuclei` ➝ `Ffuf`.
- **Intelligent Signal Handling:**
  - `1st Ctrl+C`: Gracefully skip the current tool and advance the pipeline.
  - `2nd Ctrl+C`: Instantly save state and terminate.
- **Advanced State Resumption:** Use `-r` to pick up exactly where you left off after a crash or manual stop.
- **Target-Centric Workspaces:** Automatically organizes all recon data into structured, target-named directories.
- **Live Goldmine Notifications:** Instant alerts via **Telegram**, **Slack**, or **Discord** when high-severity vulnerabilities are detected.
- **AI Triage Engine:** Auto-generates professional vulnerability reports for platforms like HackerOne and BugCrowd.
- **Omni-Update Engine:** Keeps your entire arsenal (tools and templates) updated with a single command.

---

## 🛠 Installation

```bash
# Install directly using Go
go install -v github.com/su6osec/oscar@latest
```

*Note: OSCAR will automatically provision missing dependencies from the ProjectDiscovery and tomnomnom arsenals on its first run.*

---

## 📖 Advanced Usage

### Full Recon with Live Discord Alerts
```bash
oscar -t tesla.com -b hackerone --discord https://discord.com/api/webhooks/...
```

### Resuming a Paused Pipeline
```bash
oscar -r tesla.com
```

### Agentic Mode (HexStrike AI Integration)
```bash
oscar -agent
```

---

## 📡 Notification Engine Setup

| Platform | Flag | Format |
| :--- | :--- | :--- |
| **Telegram** | `--telegram` | `BOT_TOKEN:CHAT_ID` |
| **Slack** | `--slack` | `https://hooks.slack.com/services/...` |
| **Discord** | `--discord` | `https://discord.com/api/webhooks/...` |

---

## 📊 Pipeline Map

1.  **Subfinder:** Mathematical subdomain mapping.
2.  **Dnsx:** Multi-protocol DNS interrogation.
3.  **Naabu:** High-speed port scanning.
4.  **Httpx:** Technology stack fingerprinting & response serialization.
5.  **GAU:** Historical URL extraction from archives.
6.  **Katana:** Aggressive architectural crawling.
7.  **JS Engine:** Deep analysis and isolation of `.js` logic files.
8.  **Nuclei:** Zero-day payload execution & vulnerability confirmation.
9.  **Ffuf:** Recursive directory fuzzing.
10. **Nuclei JS:** Hardcoded secret & API key exposure hunting.

---

## 🛡 Disclaimer
This tool is for educational and professional security testing purposes only. Usage of OSCAR for attacking targets without prior mutual consent is illegal.

---
Built with 💜 by the OSCAR community.
