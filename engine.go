package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
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
	ID      int
	Name    string
	Parallel bool
	Modules []Module
	PostRun func(cfg *Config, ws *Workspace) error
}

// Engine orchestrates the full scan pipeline.
type Engine struct {
	cfg    *Config
	ws     *Workspace
	stages []Stage
	stats  *ScanStats
	db     *DB
	mu     sync.Mutex // protects updateStats
	start  time.Time
}

func NewEngine(cfg *Config, ws *Workspace, db *DB) *Engine {
	e := &Engine{cfg: cfg, ws: ws, stats: &ScanStats{}, db: db, start: time.Now()}
	e.stages = buildPipeline(cfg, ws)
	return e
}

func (e *Engine) Run(ctx context.Context) error {
	printScanHeader(e.cfg)

	total := len(e.stages)
	for _, stage := range e.stages {
		if stage.ID < e.cfg.Stage {
			pterm.FgGray.Printf("  ○  Stage %d/%d  %-22s  [skipped — -stage %d]\n",
				stage.ID, total, stage.Name, e.cfg.Stage)
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
			pterm.FgGreen.Printf("  ✔  Stage %d/%d  %-22s  [cached]\n",
				stage.ID, total, stage.Name)
			continue
		}

		if err := e.runStage(ctx, stage, total); err != nil {
			return fmt.Errorf("stage %d: %w", stage.ID, err)
		}
	}

	e.printSummary()
	return nil
}

func (e *Engine) runStage(ctx context.Context, stage Stage, total int) error {
	// ── Stage banner ──────────────────────────────────────────────────────────
	mode := "parallel"
	if !stage.Parallel {
		mode = "sequential"
	}
	fmt.Println()
	fmt.Printf("  %s  Stage %d/%d  ·  %s  %s\n",
		pterm.FgCyan.Sprint("▶"),
		stage.ID, total,
		pterm.Bold.Sprint(stage.Name),
		pterm.FgGray.Sprintf("(%s)", mode))
	printDivider()

	// ── Build live UI for this stage ──────────────────────────────────────────
	names := make([]string, len(stage.Modules))
	for i, m := range stage.Modules {
		names[i] = m.Name
	}
	ui := NewStageUI(names)
	ui.Start()

	start := time.Now()
	var err error
	if stage.Parallel {
		err = e.runParallel(ctx, stage, ui)
	} else {
		err = e.runSequential(ctx, stage, ui)
	}

	ui.Stop()

	// PostRun (merge/dedup) always runs even if optional modules failed.
	if stage.PostRun != nil {
		if pErr := stage.PostRun(e.cfg, e.ws); pErr != nil {
			pterm.Warning.Printf("post-stage: %v\n", pErr)
		}
	}

	if err != nil {
		return err
	}

	elapsed := time.Since(start).Round(time.Second)
	fmt.Printf("\n  %s  Stage %d complete  %s\n",
		pterm.FgGreen.Sprint("✔"),
		stage.ID,
		pterm.FgGray.Sprintf("[%s]", elapsed))
	return nil
}

func (e *Engine) runParallel(ctx context.Context, stage Stage, ui *StageUI) error {
	var wg sync.WaitGroup
	errCh := make(chan error, len(stage.Modules))

	for _, mod := range stage.Modules {
		wg.Add(1)
		go func(m Module) {
			defer wg.Done()
			if err := e.runModule(ctx, m, ui); err != nil && !m.Optional {
				if ctx.Err() == nil {
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

func (e *Engine) runSequential(ctx context.Context, stage Stage, ui *StageUI) error {
	for _, m := range stage.Modules {
		if err := e.runModule(ctx, m, ui); err != nil && !m.Optional {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
	}
	return nil
}

func (e *Engine) runModule(ctx context.Context, m Module, ui *StageUI) error {
	// ── Resume: already done ──────────────────────────────────────────────────
	if e.cfg.Resume && e.ws.State.IsDone(m.ID) {
		ui.SetCached(m.Name, e.ws.State.GetCount(m.ID))
		return nil
	}
	if e.cfg.Resume {
		e.ws.State.ResetIfStale(m.ID)
	}

	// ── Wire live counter into context ────────────────────────────────────────
	var liveCount int64
	mctx := context.WithValue(ctx, liveCountKey{}, &liveCount)

	e.ws.State.SetRunning(m.ID)
	ui.SetRunning(m.Name, &liveCount)

	count, err := m.Run(mctx, e.cfg, e.ws)

	// Use accurate final count (runCmd may have filtered blank lines differently)
	atomic.StoreInt64(&liveCount, int64(count))

	// ── Handle result ─────────────────────────────────────────────────────────
	if err != nil {
		if ctx.Err() != nil {
			return err
		}
		ui.SetFailed(m.Name, err.Error())
		e.ws.State.SetFailed(m.ID, err.Error())
		if m.Optional {
			return nil
		}
		return err
	}

	ui.SetDone(m.Name, count)

	e.mu.Lock()
	e.ws.State.SetDone(m.ID, count)
	e.updateStats(m.ID, count)
	e.mu.Unlock()
	return nil
}

func (e *Engine) updateStats(moduleID string, count int) {
	switch moduleID {
	case "dnsx":
		e.stats.AliveHosts = count
	case "httpx":
		e.stats.WebServices = count
	case "naabu":
		e.stats.OpenPorts = count
	case "getjs":
		e.stats.JSFiles = count
	case "nuclei", "nuclei-js":
		e.stats.Vulns += count
	case "dalfox":
		e.stats.Vulns += count
	}
}

// ── Summary ───────────────────────────────────────────────────────────────────

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
	totalElapsed := time.Since(e.start).Round(time.Second)

	fmt.Println()
	printDivider()
	fmt.Printf("  %s  OSCAR v%s — %s  %s\n",
		pterm.FgGreen.Sprint("✔"),
		Version,
		pterm.Bold.Sprint(e.cfg.Target),
		pterm.FgGray.Sprintf("[total: %s]", totalElapsed))
	printDivider()
	fmt.Println()

	// Color-coded rows
	colorVal := func(n int, warn, crit int) string {
		s := fmtCount(n)
		switch {
		case n >= crit:
			return pterm.FgRed.Sprint(s)
		case n >= warn:
			return pterm.FgYellow.Sprint(s)
		default:
			return pterm.FgGreen.Sprint(s)
		}
	}

	td := pterm.TableData{
		{pterm.Bold.Sprint("Category"), pterm.Bold.Sprint("Found"), pterm.Bold.Sprint("Status")},
		{"  Subdomains (raw)",   fmtCount(e.stats.Subdomains), statusBar(e.stats.Subdomains, 500, 2000)},
		{"  Alive Hosts",        fmtCount(e.stats.AliveHosts), statusBar(e.stats.AliveHosts, 100, 500)},
		{"  Web Services",       fmtCount(e.stats.WebServices), statusBar(e.stats.WebServices, 50, 200)},
		{"  Open Ports",         fmtCount(e.stats.OpenPorts), statusBar(e.stats.OpenPorts, 20, 100)},
		{"  URLs Collected",     fmtCount(e.stats.URLs), statusBar(e.stats.URLs, 1000, 10000)},
		{"  JS Files",           fmtCount(e.stats.JSFiles), statusBar(e.stats.JSFiles, 20, 100)},
		{"  Vulnerabilities",    colorVal(e.stats.Vulns, 1, 5), vulnStatus(e.stats.Vulns)},
		{"  Secrets Found",      colorVal(e.stats.Secrets, 1, 5), secretStatus(e.stats.Secrets)},
		{"  Directories",        fmtCount(e.stats.Dirs), statusBar(e.stats.Dirs, 100, 1000)},
	}

	pterm.DefaultTable.WithHasHeader().WithBoxed().WithData(td).Render() //nolint:errcheck
	fmt.Printf("\n  Reports → %s\n\n", pterm.FgCyan.Sprint(e.ws.Root))
}

func statusBar(n, warn, high int) string {
	const width = 12
	var filled int
	switch {
	case n == 0:
		return pterm.FgGray.Sprint("─────────────")
	case n >= high:
		filled = width
	case n >= warn:
		filled = width * n / high
	default:
		filled = width * n / (warn + 1)
	}
	if filled < 1 {
		filled = 1
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	switch {
	case n >= high:
		return pterm.FgCyan.Sprint(bar)
	case n >= warn:
		return pterm.FgYellow.Sprint(bar)
	default:
		return pterm.FgGray.Sprint(bar)
	}
}

func vulnStatus(n int) string {
	switch {
	case n == 0:
		return pterm.FgGreen.Sprint("● CLEAN")
	case n < 5:
		return pterm.FgYellow.Sprint("▲ REVIEW")
	default:
		return pterm.FgRed.Sprint("✘ CRITICAL")
	}
}

func secretStatus(n int) string {
	switch {
	case n == 0:
		return pterm.FgGreen.Sprint("● NONE")
	case n < 3:
		return pterm.FgYellow.Sprint("▲ CHECK")
	default:
		return pterm.FgRed.Sprint("✘ EXPOSED")
	}
}

// ── Scan header ───────────────────────────────────────────────────────────────

func printScanHeader(cfg *Config) {
	fmt.Println()

	// Mode badge
	var modeBadge string
	switch {
	case cfg.Fast:
		modeBadge = pterm.NewStyle(pterm.FgBlack, pterm.BgYellow).Sprint(" ⚡ FAST ")
	case cfg.Deep:
		modeBadge = pterm.NewStyle(pterm.FgBlack, pterm.BgCyan).Sprint(" ◎ DEEP ")
	default:
		modeBadge = pterm.NewStyle(pterm.FgBlack, pterm.BgGray).Sprint(" ● SCAN ")
	}

	info := fmt.Sprintf("threads: %d  ·  timeout: %dm  ·  format: %s",
		cfg.Threads, cfg.Timeout, cfg.Format)

	pterm.DefaultBox.
		WithTitle(" TARGET ").
		WithTitleTopCenter().
		WithRightPadding(4).
		WithLeftPadding(4).
		Printf("%s\n\n%s\n%s",
			pterm.FgLightCyan.Sprint(cfg.Target),
			modeBadge,
			pterm.FgGray.Sprint(info))
	fmt.Println()
}

func printDivider() {
	fmt.Printf("  %s\n", pterm.FgGray.Sprint(strings.Repeat("─", 52)))
}
