package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/pterm/pterm"
)

// ModuleFunc is the signature every module implements.
type ModuleFunc func(ctx context.Context, cfg *Config, ws *Workspace) (int, error)

// Module defines a single unit of work in the pipeline.
type Module struct {
	ID       string
	Name     string
	Optional bool
	Run      ModuleFunc
}

// Stage groups related modules.
type Stage struct {
	ID        int
	Name      string
	Parallel  bool
	Modules   []Module
	PostRun   func(cfg *Config, ws *Workspace) error
}

// Engine orchestrates the full scan pipeline.
type Engine struct {
	cfg    *Config
	ws     *Workspace
	stages []Stage
	stats  *ScanStats
	db     *DB
	mu     sync.Mutex // serialises terminal output across parallel goroutines
}

func NewEngine(cfg *Config, ws *Workspace, db *DB) *Engine {
	e := &Engine{cfg: cfg, ws: ws, stats: &ScanStats{}, db: db}
	e.stages = buildPipeline(cfg, ws)
	return e
}

func (e *Engine) Run(ctx context.Context) error {
	printScanHeader(e.cfg.Target)

	for _, stage := range e.stages {
		if stage.ID < e.cfg.Stage {
			pterm.FgGray.Printf("  ○ Stage %d: %-25s [skipped — -stage %d]\n", stage.ID, stage.Name, e.cfg.Stage)
			continue
		}

		allDone := true
		for _, m := range stage.Modules {
			if !e.ws.State.IsDone(m.ID) {
				allDone = false
				break
			}
		}
		if allDone && e.cfg.Resume {
			pterm.FgGreen.Printf("  ✓ Stage %d: %-25s [cached]\n", stage.ID, stage.Name)
			continue
		}

		if err := e.runStage(ctx, stage); err != nil {
			return fmt.Errorf("stage %d: %w", stage.ID, err)
		}
	}

	e.printSummary()
	return nil
}

func (e *Engine) runStage(ctx context.Context, stage Stage) error {
	pterm.DefaultSection.WithTopPadding(1).Printf("Stage %d  ·  %s", stage.ID, stage.Name)

	start := time.Now()
	var err error

	if stage.Parallel {
		err = e.runParallel(ctx, stage)
	} else {
		err = e.runSequential(ctx, stage)
	}

	// Always run PostRun (merge/dedup) even if some optional modules failed.
	// This ensures stage 1 subdomains are merged even when crt.sh is skipped.
	if stage.PostRun != nil {
		if pErr := stage.PostRun(e.cfg, e.ws); pErr != nil {
			pterm.Warning.Printf("post-stage cleanup: %v\n", pErr)
		}
	}

	if err != nil {
		return err
	}

	elapsed := time.Since(start).Round(time.Second)
	pterm.FgGreen.Printf("  ✓ Stage %d complete in %s\n", stage.ID, elapsed)
	return nil
}

func (e *Engine) runParallel(ctx context.Context, stage Stage) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(stage.Modules))

	for _, mod := range stage.Modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			if err := e.runModule(ctx, m); err != nil && !m.Optional {
				if ctx.Err() == nil { // don't propagate errors caused by Ctrl+C / context cancel
					errCh <- err
				}
			}
		}(mod)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		return err
	}
	return nil
}

func (e *Engine) runSequential(ctx context.Context, stage Stage) error {
	for _, m := range stage.Modules {
		if err := e.runModule(ctx, m); err != nil && !m.Optional {
			if ctx.Err() != nil {
				return nil // interrupted by Ctrl+C, exit gracefully
			}
			return err
		}
	}
	return nil
}

func (e *Engine) runModule(ctx context.Context, m Module) error {
	if e.cfg.Resume {
		if e.ws.State.IsDone(m.ID) {
			e.mu.Lock()
			pterm.FgGreen.Printf("  ✓ %-22s [cached: %d]\n", m.Name, e.ws.State.GetCount(m.ID))
			e.mu.Unlock()
			return nil
		}
		// A "Running" state means the previous run was interrupted mid-module; reset it.
		e.ws.State.ResetIfStale(m.ID)
	}

	e.ws.State.SetRunning(m.ID)
	count, err := m.Run(ctx, e.cfg, e.ws)

	e.mu.Lock()
	defer e.mu.Unlock()

	if err != nil {
		if ctx.Err() != nil {
			return err // context canceled — runSequential/runParallel will suppress the print
		}
		pterm.Error.Printf("  ✗ %-22s  %v\n", m.Name, err)
		e.ws.State.SetFailed(m.ID, err.Error())
		if m.Optional {
			return nil
		}
		return err
	}

	label := fmt.Sprintf("%-22s", m.Name)
	pterm.Success.Printf("  %s  → %d results\n", label, count)
	e.ws.State.SetDone(m.ID, count)
	e.updateStats(m.ID, count)
	return nil
}

func (e *Engine) updateStats(moduleID string, count int) {
	switch moduleID {
	case "subfinder", "assetfinder", "crtsh":
		// counted at merge
	case "dnsx":
		e.stats.AliveHosts = count
	case "httpx":
		e.stats.WebServices = count
	case "naabu":
		e.stats.OpenPorts = count
	case "gau", "katana":
		// counted at merge
	case "getjs":
		e.stats.JSFiles = count
	case "nuclei", "nuclei-js":
		e.stats.Vulns += count
	case "dalfox":
		e.stats.Vulns += count
	}
}

func (e *Engine) printSummary() {
	e.stats.Subdomains = CountLines(e.ws.RawSubdomains)
	e.stats.AliveHosts = CountLines(e.ws.AliveHosts)
	e.stats.WebServices = CountLines(e.ws.LiveWeb)
	e.stats.OpenPorts = CountLines(e.ws.OpenPorts)
	e.stats.URLs = CountLines(e.ws.AllURLs)
	e.stats.JSFiles = CountLines(e.ws.JSFiles)
	e.stats.Vulns = CountLines(e.ws.NucleiHits) + CountLines(e.ws.XSSHits)
	e.stats.Secrets = CountLines(e.ws.Secrets)
	e.stats.Dirs = CountLines(e.ws.Dirs)

	fmt.Println()
	pterm.DefaultHeader.WithBackgroundStyle(pterm.NewStyle(pterm.BgDarkGray)).
		Printf(" OSCAR v%s — Scan Complete: %s ", Version, e.cfg.Target)
	fmt.Println()

	td := pterm.TableData{
		{"Category", "Count"},
		{"Subdomains (raw)", fmt.Sprintf("%d", e.stats.Subdomains)},
		{"Alive Hosts", fmt.Sprintf("%d", e.stats.AliveHosts)},
		{"Web Services", fmt.Sprintf("%d", e.stats.WebServices)},
		{"Open Ports", fmt.Sprintf("%d", e.stats.OpenPorts)},
		{"URLs Collected", fmt.Sprintf("%d", e.stats.URLs)},
		{"JS Files", fmt.Sprintf("%d", e.stats.JSFiles)},
		{"Vulnerabilities", fmt.Sprintf("%d", e.stats.Vulns)},
		{"Secrets Found", fmt.Sprintf("%d", e.stats.Secrets)},
		{"Directories", fmt.Sprintf("%d", e.stats.Dirs)},
	}

	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(td).Render() //nolint:errcheck
	fmt.Printf("\n  Reports saved to: %s\n\n", e.ws.Root)
}

func printScanHeader(target string) {
	fmt.Println()
	pterm.DefaultBox.WithTitle(" TARGET ").
		WithTitleTopCenter().
		WithRightPadding(4).
		WithLeftPadding(4).
		Println(pterm.FgLightCyan.Sprint(target))
	fmt.Println()

	_ = os.Stdout
}
