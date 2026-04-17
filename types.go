package main

import "time"

const Version = "2.0.0"

// Config holds all runtime configuration for a scan.
type Config struct {
	Target  string
	Threads int
	Timeout int
	Format  string
	NoAI    bool
	Resume  bool
	Stage   int
	Fast    bool // skip slow optional tools: alterx, ffuf, dalfox
	Deep    bool // enable all tools including slow ones (default when neither flag set)
}

// Finding is a single result emitted by any module.
type Finding struct {
	Module   string
	Type     string // subdomain, host, port, url, vuln, secret, dir
	Host     string
	URL      string
	Severity string
	Detail   string
	Raw      string
	Time     time.Time
}

// ScanStats accumulates counts across all stages.
type ScanStats struct {
	Subdomains  int
	AliveHosts  int
	WebServices int
	OpenPorts   int
	URLs        int
	JSFiles     int
	Vulns       int
	Secrets     int
	Dirs        int
}
