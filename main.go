package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/pterm/pterm"
)

func main() {
	var (
		target  = flag.String("t", "", "Target domain (e.g. tesla.com)")
		update  = flag.Bool("up", false, "Install / update all required tools")
		format  = flag.String("f", "md", "Report format: txt, md, json, csv, pdf")
		threads = flag.Int("threads", 50, "Concurrent threads per module")
		timeout = flag.Int("timeout", 30, "Per-module timeout in minutes")
		noAI    = flag.Bool("no-ai", false, "Skip Ollama AI triage")
		resume  = flag.Bool("resume", false, "Resume a previous scan (skip completed stages)")
		stage   = flag.Int("stage", 1, "Start from a specific stage (1–5)")
		mcp     = flag.Bool("mcp", false, "Print MCP server configuration for Claude/Cursor")
		ver     = flag.Bool("v", false, "Show version and exit")
	)

	flag.Usage = printUsage
	flag.Parse()

	if *ver {
		fmt.Printf("OSCAR v%s\n", Version)
		return
	}

	printBanner()

	if *mcp {
		printMCPConfig()
		return
	}

	if *update {
		RunInstaller()
		return
	}

	if *target == "" {
		flag.Usage()
		os.Exit(1)
	}

	cfg := &Config{
		Target:  *target,
		Threads: *threads,
		Timeout: *timeout,
		Format:  *format,
		NoAI:    *noAI,
		Resume:  *resume,
		Stage:   *stage,
	}

	RunScan(cfg)
}

// RunScan sets up and executes the full pipeline for the given config.
func RunScan(cfg *Config) {
	// Open database
	db, err := OpenDB("oscar.db")
	if err != nil {
		pterm.Warning.Printf("Database unavailable: %v — continuing without persistence\n", err)
	} else {
		defer db.Close()
	}

	// Set up workspace
	ws, err := NewWorkspace(cfg.Target)
	if err != nil {
		pterm.Fatal.Printf("Cannot create workspace: %v\n", err)
	}

	// Track in DB
	var scanID int64
	if db != nil {
		scanID, _ = db.StartScan(cfg.Target)
	}

	// Context with graceful cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle Ctrl+C: first press cancels, second press exits hard
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		count := 0
		for range sigCh {
			count++
			if count == 1 {
				pterm.Warning.Println("Interrupt received — stopping current module gracefully. Press Ctrl+C again to force exit.")
				cancel()
			} else {
				pterm.Error.Println("Force exit. State has been saved.")
				os.Exit(1)
			}
		}
	}()

	// Build and run the engine
	engine := NewEngine(cfg, ws, db)
	if err := engine.Run(ctx); err != nil {
		pterm.Error.Printf("Scan failed: %v\n", err)
	}

	// Generate report
	if db != nil {
		db.FinishScan(scanID)
	}

	GenerateReport(cfg, ws, cfg.NoAI)
}

func printBanner() {
	// Gradient ASCII art banner
	gradient := []string{
		"\033[38;5;93m",
		"\033[38;5;99m",
		"\033[38;5;105m",
		"\033[38;5;111m",
		"\033[38;5;117m",
		"\033[38;5;123m",
	}

	lines := []string{
		`   ██████╗ ███████╗ ██████╗ █████╗ ██████╗ `,
		`  ██╔═══██╗██╔════╝██╔════╝██╔══██╗██╔══██╗`,
		`  ██║   ██║███████╗██║     ███████║██████╔╝`,
		`  ██║   ██║╚════██║██║     ██╔══██║██╔══██╗`,
		`  ╚██████╔╝███████║╚██████╗██║  ██║██║  ██║`,
		`   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝`,
	}

	fmt.Println()
	for i, line := range lines {
		color := gradient[i%len(gradient)]
		fmt.Printf("%s%s\033[0m\n", color, line)
	}

	fmt.Printf("\033[38;5;141m  %-44s\033[0m\n", fmt.Sprintf("Omni-Signal Capture & Agentic Recon  v%s", Version))
	fmt.Printf("\033[38;5;245m  %-44s\033[0m\n", "github.com/su6osec/oscar")
	fmt.Println()
}

func printUsage() {
	printBanner()
	pterm.DefaultHeader.WithFullWidth().Println(" Usage ")

	fmt.Println()
	pterm.DefaultSection.Println("Scanning")
	fmt.Println("  -t <domain>    Target domain to recon  (e.g. tesla.com)")
	fmt.Println("  -threads <n>   Concurrent threads per module  [default: 50]")
	fmt.Println("  -timeout <n>   Per-module timeout in minutes  [default: 30]")
	fmt.Println("  -stage <n>     Start from stage 1–5           [default: 1]")
	fmt.Println("  -resume        Resume a previous scan")

	fmt.Println()
	pterm.DefaultSection.Println("Output")
	fmt.Println("  -f <format>    Report format: txt, md, json, csv, pdf  [default: md]")
	fmt.Println("  -no-ai         Skip Ollama AI triage")

	fmt.Println()
	pterm.DefaultSection.Println("System")
	fmt.Println("  -up            Install / update all required tools")
	fmt.Println("  -mcp           Print MCP configuration for Claude/Cursor")
	fmt.Println("  -v             Show version")

	fmt.Println()
	pterm.DefaultSection.Println("Pipeline Stages")
	stages := []string{
		"1  Passive Discovery   subfinder, assetfinder, crt.sh",
		"2  DNS Resolution      dnsx, alterx",
		"3  Service Mapping     naabu, httpx, tlsx",
		"4  Content Discovery   gau, katana, getJS, ffuf",
		"5  Vuln Analysis       nuclei, dalfox, nuclei-js",
	}
	for _, s := range stages {
		fmt.Printf("   %s\n", s)
	}
	fmt.Println()
}
