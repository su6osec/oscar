# OSCAR - Open-Source Cyber Attack Reconnaissance

OSCAR is a blazing fast, lightweight, and pure CLI-based HTTP probing and reconnaissance tool designed specifically for Cybersecurity Engineers and Bug Bounty Hunters. Built entirely in Go, it focuses on extreme speed, high concurrency, and Unix pipeline philosophy.

## Features
- **Lightning Fast HTTP Probing**: Checks massive lists of domains concurrently to find live web servers.
- **Pure CLI**: Designed to be piped with other tools natively. No bloated web UI, just pure speed.
- **Smart Data Extraction**: Automatically extracts server-side headers and web page titles.
- **Zero Configuration**: A single static binary with single-character flags.

## Installation

Install OSCAR via native Go package manager in a single command:

```bash
go install github.com/su6osec/oscar@latest
```

## Usage

OSCAR takes targets from standard input or a file and probes them concurrently.

```bash
oscar -h
```

### Basic HTTP Probing
```bash
cat domains.txt | oscar
```

### High Concurrency
Ramp up the concurrency with the `-c` flag for larger lists.
```bash
cat subdomains.txt | oscar -c 100
```

### Advanced V2 Features
OSCAR now ships with an integrated Vulnerability Engine and JSON support!
- **Vuln Scanning (`-x`)**: Automatically hunts for exposed `.env` and `.git/config` files on discovered live hosts!
- **JSON Format (`-j`)**: Flawlessly pipes into CLI JSON parsers like `jq`.
```bash
cat targets.txt | oscar -x -j | jq .
```

### Silent Mode
Pipes out only live URLs to stdout, stripping the console formatting so you can pipe the output directly into other tools (like Nuclei) with the `-s` flag.
```bash
oscar -f targets.txt -s > live_hosts.txt
```

### Allow Redirects
Use the `-r` flag to allow HTTP redirects on probed URLs.

## Open Source
OSCAR is 100% free, open-source, and created to make attack surface management fluid.

## License
MIT License
