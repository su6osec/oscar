package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pterm/pterm"
	"golang.org/x/term"
)

// liveCountKey threads a live line-counter through context into runCmd.
type liveCountKey struct{}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

type rowState int8

const (
	stPending rowState = iota
	stRunning
	stDone
	stFailed
	stCached
)

type modRow struct {
	name     string
	state    rowState
	countPtr *int64
	count    int64
	start    time.Time
	elapsed  time.Duration
	errMsg   string
}

// StageUI renders a live-updating terminal block for one pipeline stage.
// In TTY mode it uses a pterm.Area that redraws every 80 ms; in non-TTY it
// falls back to plain line prints with its own mutex to avoid interleaving.
type StageUI struct {
	mu      sync.RWMutex
	printMu sync.Mutex
	rows    []*modRow
	byName  map[string]*modRow
	area    *pterm.AreaPrinter
	isTTY   bool
	spinIdx int
	stopCh  chan struct{}
	doneCh  chan struct{}
}

func NewStageUI(names []string) *StageUI {
	rows := make([]*modRow, len(names))
	byName := make(map[string]*modRow, len(names))
	for i, n := range names {
		r := &modRow{name: n, state: stPending}
		rows[i] = r
		byName[n] = r
	}
	return &StageUI{
		rows:   rows,
		byName: byName,
		isTTY:  term.IsTerminal(int(os.Stdout.Fd())),
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

func (u *StageUI) Start() {
	if !u.isTTY {
		close(u.doneCh)
		return
	}
	var err error
	u.area, err = pterm.DefaultArea.Start()
	if err != nil {
		u.isTTY = false
		close(u.doneCh)
		return
	}
	go u.loop()
}

func (u *StageUI) loop() {
	defer close(u.doneCh)
	t := time.NewTicker(80 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-u.stopCh:
			u.area.Update(u.frame())
			return
		case <-t.C:
			u.area.Update(u.frame())
		}
	}
}

func (u *StageUI) frame() string {
	u.mu.RLock()
	u.spinIdx = (u.spinIdx + 1) % len(spinFrames)
	spin := spinFrames[u.spinIdx]
	rows := make([]*modRow, len(u.rows))
	copy(rows, u.rows)
	u.mu.RUnlock()

	var sb strings.Builder
	for _, r := range rows {
		switch r.state {
		case stPending:
			continue
		case stRunning:
			n := int64(0)
			if r.countPtr != nil {
				n = atomic.LoadInt64(r.countPtr)
			}
			elapsed := time.Since(r.start).Round(time.Second)
			fmt.Fprintf(&sb, "  %s %-22s  %s  %s\n",
				pterm.FgYellow.Sprint(spin),
				pterm.FgYellow.Sprint(r.name),
				pterm.FgCyan.Sprintf("→ %s found", fmtCount(int(n))),
				pterm.FgGray.Sprintf("[%s]", elapsed))
		case stDone:
			fmt.Fprintf(&sb, "  %s %-22s  %s  %s\n",
				pterm.FgGreen.Sprint("✔"),
				pterm.FgGreen.Sprint(r.name),
				pterm.FgGreen.Sprintf("→ %s", fmtCount(int(r.count))),
				pterm.FgGray.Sprintf("[%s]", r.elapsed.Round(time.Second)))
		case stFailed:
			fmt.Fprintf(&sb, "  %s %-22s  %s\n",
				pterm.FgRed.Sprint("✘"),
				pterm.FgRed.Sprint(r.name),
				pterm.FgRed.Sprint(r.errMsg))
		case stCached:
			fmt.Fprintf(&sb, "  %s %-22s  %s\n",
				pterm.FgGreen.Sprint("✔"),
				pterm.FgGray.Sprint(r.name),
				pterm.FgGray.Sprintf("[cached · %s]", fmtCount(int(r.count))))
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}

func (u *StageUI) SetRunning(name string, ctr *int64) {
	u.mu.Lock()
	if r, ok := u.byName[name]; ok {
		r.state = stRunning
		r.start = time.Now()
		r.countPtr = ctr
	}
	u.mu.Unlock()
	if !u.isTTY {
		u.printMu.Lock()
		pterm.FgYellow.Printf("  %s %-22s  starting…\n", spinFrames[0], name)
		u.printMu.Unlock()
	}
}

func (u *StageUI) SetDone(name string, count int) {
	u.mu.Lock()
	if r, ok := u.byName[name]; ok {
		r.state = stDone
		atomic.StoreInt64(&r.count, int64(count))
		r.countPtr = nil
		r.elapsed = time.Since(r.start)
	}
	u.mu.Unlock()
	if !u.isTTY {
		u.printMu.Lock()
		pterm.Success.Printf("  %-22s  → %s\n", name, fmtCount(count))
		u.printMu.Unlock()
	}
}

func (u *StageUI) SetFailed(name string, msg string) {
	u.mu.Lock()
	if r, ok := u.byName[name]; ok {
		r.state = stFailed
		r.errMsg = msg
		r.countPtr = nil
		r.elapsed = time.Since(r.start)
	}
	u.mu.Unlock()
	if !u.isTTY {
		u.printMu.Lock()
		pterm.Error.Printf("  ✘ %-22s  %s\n", name, msg)
		u.printMu.Unlock()
	}
}

func (u *StageUI) SetCached(name string, count int) {
	u.mu.Lock()
	if r, ok := u.byName[name]; ok {
		r.state = stCached
		atomic.StoreInt64(&r.count, int64(count))
		r.countPtr = nil
	}
	u.mu.Unlock()
	if !u.isTTY {
		u.printMu.Lock()
		pterm.FgGreen.Printf("  ✔ %-22s  [cached · %s]\n", name, fmtCount(count))
		u.printMu.Unlock()
	}
}

// Stop halts the renderer and prints permanent final lines.
func (u *StageUI) Stop() {
	if !u.isTTY {
		return
	}
	close(u.stopCh)
	<-u.doneCh
	u.area.Stop()
	u.printFinal()
}

func (u *StageUI) printFinal() {
	u.mu.RLock()
	defer u.mu.RUnlock()
	for _, r := range u.rows {
		switch r.state {
		case stDone:
			pterm.Success.Printf("  %-22s  → %s  [%s]\n",
				r.name, fmtCount(int(r.count)), r.elapsed.Round(time.Second))
		case stFailed:
			pterm.Error.Printf("  ✘ %-22s  %s\n", r.name, r.errMsg)
		case stCached:
			pterm.FgGreen.Printf("  ✔ %s  [cached · %s]\n",
				pterm.FgGray.Sprintf("%-22s", r.name), fmtCount(int(r.count)))
		}
	}
}

// fmtCount formats an integer with K/M suffix.
func fmtCount(n int) string {
	switch {
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", float64(n)/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", float64(n)/1_000)
	default:
		return fmt.Sprintf("%d", n)
	}
}

// isTerminal reports whether f is an interactive terminal.
func isTerminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd()))
}
