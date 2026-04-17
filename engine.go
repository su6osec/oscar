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
			pterm.FgGray.Printf("  ○ Stage %d: %-25s [skipped — resume]\n", stage.ID, stage.Name)
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

	if err != nil {
		return err
	}

	if stage.PostRun != nil {
		if pErr := stage.PostRun(e.cfg, e.ws); pErr != nil {
			pterm.Warning.Printf("post-stage cleanup: %v\n", pErr)
		}
	}

	elapsed := time.Since(start).Round(time.Second)
	pterm.FgGreen.Printf("  ✓ Stage %d complete in %s\n\n", stage.ID, elapsed)
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
				errCh <- err
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
			return err
		}
	}
	return nil
}

func (e *Engine) runModule(ctx context.Context, m Module) error {
	if e.ws.State.IsDone(m.ID) && e.cfg.Resume {
		count := e.ws.State.GetCount(m.ID)
		pterm.FgGreen.Printf("  ✓ %-20s [cached: %d]\n", m.Name, count)
		return nil
	}

	spinner, _ := pterm.DefaultSpinner.
		WithRemoveWhenDone(false).
		WithShowTimer(true).
		Start(fmt.Sprintf("  %-20s", m.Name))

	e.ws.State.SetRunning(m.ID)

	count, err := m.Run(ctx, e.cfg, e.ws)

	if err != nil {
		spinner.Fail(fmt.Sprintf("  %-20s  ✗ %v", m.Name, err))
		e.ws.State.SetFailed(m.ID, err.Error())
		if m.Optional {
			return nil
		}
		return err
	}

	spinner.Success(fmt.Sprintf("  %-20s  → %s%d results%s", m.Name,
		pterm.FgCyan.Sprint(""), count, pterm.Reset.Sprint("")))
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
	pterm.DefaultHeader.WithFullWidth().WithBackgroundStyle(pterm.NewStyle(pterm.BgDarkGray)).
		Printf(" OSCAR V%s — Scan Complete: %s ", Version, e.cfg.Target)
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
