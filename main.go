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
		fast    = flag.Bool("fast", false, "Fast mode: skip alterx, ffuf, dalfox (~3× faster)")
		deep    = flag.Bool("deep", false, "Deep mode: enable all tools including slow ones")
		agent   = flag.Bool("agent", false, "Show MCP / agentic setup guide for Claude, Cursor, etc.")
		mcp     = flag.Bool("mcp", false, "Alias for -agent")
		ver     = flag.Bool("v", false, "Show version and exit")
	)

	flag.Usage = printUsage
	flag.Parse()

	if *ver {
		fmt.Printf("OSCAR v%s\n", Version)
		return
	}

	printBanner()

	// -agent and -mcp are the same
	if *agent || *mcp {
		printAgentSetup()
		return
	}

	if *update {
		// Banner already printed above — RunInstaller must NOT print it again
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
		Fast:    *fast,
		Deep:    *deep,
	}

	RunScan(cfg)
}

// RunScan sets up and executes the full pipeline for the given config.
func RunScan(cfg *Config) {
	db, err := OpenDB("oscar.db")
	if err != nil {
		pterm.Warning.Printf("Database unavailable: %v — continuing without persistence\n", err)
	} else {
		defer db.Close()
	}

	ws, err := NewWorkspace(cfg.Target)
	if err != nil {
		pterm.Fatal.Printf("Cannot create workspace: %v\n", err)
	}

	var scanID int64
	if db != nil {
		scanID, _ = db.StartScan(cfg.Target)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Dual Ctrl+C: graceful cancel → hard exit
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		count := 0
		for range sigCh {
			count++
			if count == 1 {
				pterm.Warning.Println("Interrupt — stopping current module. Press Ctrl+C again to force exit.")
				cancel()
			} else {
				pterm.Error.Println("Force exit. State saved.")
				os.Exit(1)
			}
		}
	}()

	engine := NewEngine(cfg, ws, db)
	if err := engine.Run(ctx); err != nil {
		pterm.Error.Printf("Scan error: %v\n", err)
	}

	if db != nil {
		db.FinishScan(scanID)
	}

	GenerateReport(cfg, ws, cfg.NoAI)
}

// ─── Visual elements ──────────────────────────────────────────────────────────

func printBanner() {
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
		fmt.Printf("%s%s\033[0m\n", gradient[i%len(gradient)], line)
	}
	fmt.Printf("\033[38;5;141m  %-44s\033[0m\n", fmt.Sprintf("Omni-Signal Capture & Agentic Recon  v%s", Version))
	fmt.Printf("\033[38;5;245m  %-44s\033[0m\n", "github.com/su6osec/oscar")
	fmt.Println()
}

func printUsage() {
	pterm.DefaultHeader.WithFullWidth().Println("  Usage  ")

	fmt.Println()
	pterm.DefaultSection.Println("Scanning")
	fmt.Println("  -t <domain>    Target domain                       e.g. tesla.com")
	fmt.Println("  -threads <n>   Threads per module                  [default: 50]")
	fmt.Println("  -timeout <n>   Per-module timeout (minutes)        [default: 30]")
	fmt.Println("  -stage <n>     Start from stage 1–5                [default: 1]")
	fmt.Println("  -resume        Resume a previous scan")
	fmt.Println("  -fast          Skip alterx/ffuf/dalfox (~3× faster)")
	fmt.Println("  -deep          Enable all tools including slow permutation/brute-force")

	fmt.Println()
	pterm.DefaultSection.Println("Output")
	fmt.Println("  -f <format>    Report format: txt, md, json, csv, pdf  [default: md]")
	fmt.Println("  -no-ai         Skip Ollama AI triage")

	fmt.Println()
	pterm.DefaultSection.Println("System")
	fmt.Println("  -up            Install / update all required tools")
	fmt.Println("  -agent         MCP setup guide for Claude, Cursor, Windsurf, etc.")
	fmt.Println("  -v             Show version")

	fmt.Println()
	pterm.DefaultSection.Println("Pipeline")
	for _, s := range []string{
		"1  Passive Discovery   subfinder · assetfinder · crt.sh",
		"2  DNS Resolution      dnsx · alterx",
		"3  Service Mapping     naabu · httpx · tlsx",
		"4  Content Discovery   gau · katana · getJS · ffuf",
		"5  Vuln Analysis       nuclei · dalfox · nuclei-js",
	} {
		fmt.Printf("   %s\n", s)
	}
	fmt.Println()
}
