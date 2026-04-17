package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// ─── Pipeline Builder ──────────────────────────────────────────────────────────

func buildPipeline(cfg *Config, ws *Workspace) []Stage {
	return []Stage{
		{
			ID:       1,
			Name:     "Passive Discovery",
			Parallel: true,
			Modules: []Module{
				{ID: "subfinder", Name: "Subfinder", Run: runSubfinder},
				{ID: "assetfinder", Name: "Assetfinder", Optional: true, Run: runAssetfinder},
				{ID: "crtsh", Name: "Crt.sh", Run: runCrtsh},
			},
			PostRun: func(c *Config, w *Workspace) error {
				n, err := MergeDedup(w.RawSubdomains, w.SubfinderOut, w.AssetfinderOut, w.CrtshOut)
				if err == nil {
					fmt.Printf("  ► Merged passive discovery: %d unique subdomains\n", n)
				}
				return err
			},
		},
		{
			ID:       2,
			Name:     "DNS Resolution",
			Parallel: false,
			Modules: []Module{
				{ID: "dnsx", Name: "Dnsx", Run: runDnsx},
				{ID: "alterx", Name: "Alterx", Optional: true, Run: runAlterx},
			},
		},
		{
			ID:       3,
			Name:     "Service Mapping",
			Parallel: true,
			Modules: []Module{
				{ID: "naabu", Name: "Naabu", Run: runNaabu},
				{ID: "httpx", Name: "Httpx", Run: runHttpx},
				{ID: "tlsx", Name: "Tlsx", Optional: true, Run: runTlsx},
			},
		},
		{
			ID:       4,
			Name:     "Content Discovery",
			Parallel: true,
			Modules: []Module{
				{ID: "gau", Name: "GAU", Run: runGau},
				{ID: "katana", Name: "Katana", Run: runKatana},
				{ID: "getjs", Name: "GetJS", Optional: true, Run: runGetJS},
				{ID: "ffuf", Name: "Ffuf", Optional: true, Run: runFfuf},
			},
			PostRun: func(c *Config, w *Workspace) error {
				n, err := MergeDedup(w.AllURLs, w.HistoricalURLs, w.CrawledURLs)
				if err == nil {
					fmt.Printf("  ► Merged URLs: %d unique endpoints\n", n)
				}
				return err
			},
		},
		{
			ID:       5,
			Name:     "Vulnerability Analysis",
			Parallel: true,
			Modules: []Module{
				{ID: "nuclei", Name: "Nuclei", Run: runNuclei},
				{ID: "nuclei-js", Name: "Nuclei JS", Optional: true, Run: runNucleiJS},
				{ID: "dalfox", Name: "Dalfox", Optional: true, Run: runDalfox},
			},
		},
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

// runCmd executes a command, streaming stdout lines to outFile. Returns line count.
func runCmd(ctx context.Context, outFile string, args ...string) (int, error) {
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stderr = nil

	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return 0, err
	}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("%s not found or failed to start: %w", args[0], err)
	}

	f, err := os.Create(outFile)
	if err != nil {
		cmd.Process.Kill() //nolint:errcheck
		return 0, err
	}
	defer f.Close()

	count := 0
	sc := bufio.NewScanner(pipe)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			f.WriteString(line + "\n") //nolint:errcheck
			count++
		}
	}

	cmd.Wait() //nolint:errcheck
	return count, nil
}

// filterLines reads src, applies filter, writes matching lines to dst.
func filterLines(src, dst string, filter func(string) string) (int, error) {
	in, err := os.Open(src)
	if err != nil {
		return 0, err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer out.Close()

	count := 0
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		if result := filter(sc.Text()); result != "" {
			out.WriteString(result + "\n") //nolint:errcheck
			count++
		}
	}
	return count, nil
}

// withTimeout wraps a context with the configured timeout in minutes.
func withTimeout(ctx context.Context, cfg *Config) (context.Context, context.CancelFunc) {
	d := time.Duration(cfg.Timeout) * time.Minute
	if d == 0 {
		d = 30 * time.Minute
	}
	return context.WithTimeout(ctx, d)
}

// ─── Stage 1: Passive Discovery ───────────────────────────────────────────────

func runSubfinder(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.SubfinderOut,
		FindTool("subfinder"), "-d", cfg.Target, "-silent", "-all")
}

func runAssetfinder(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.AssetfinderOut,
		FindTool("assetfinder"), "--subs-only", cfg.Target)
}

type crtEntry struct {
	NameValue string `json:"name_value"`
}

func runCrtsh(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	url := fmt.Sprintf("https://crt.sh/?q=%%.%s&output=json", cfg.Target)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "OSCAR/"+Version)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	var entries []crtEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return 0, fmt.Errorf("crt.sh parse: %w", err)
	}

	seen := make(map[string]bool)
	var lines []string
	for _, e := range entries {
		for _, name := range strings.Split(e.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name != "" && strings.HasSuffix(name, cfg.Target) && !seen[name] {
				seen[name] = true
				lines = append(lines, name)
			}
		}
	}

	content := strings.Join(lines, "\n")
	if len(lines) > 0 {
		content += "\n"
	}
	return len(lines), os.WriteFile(ws.CrtshOut, []byte(content), 0644)
}

// ─── Stage 2: DNS Resolution ──────────────────────────────────────────────────

func runDnsx(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	if !FileExists(ws.RawSubdomains) {
		return 0, fmt.Errorf("no subdomains to resolve (Stage 1 may have found nothing)")
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()

	// Run dnsx to resolve and get A records
	n, err := runCmd(tctx, ws.AliveHosts,
		FindTool("dnsx"), "-silent", "-l", ws.RawSubdomains,
		"-a", "-resp", "-threads", fmt.Sprintf("%d", cfg.Threads))
	if err != nil {
		return 0, err
	}

	// Extract just hostnames (dnsx outputs "host [ip]")
	clean := ws.AliveHosts + ".clean"
	_, _ = filterLines(ws.AliveHosts, clean, func(line string) string {
		parts := strings.Fields(line)
		if len(parts) > 0 {
			return parts[0]
		}
		return ""
	})
	os.Rename(clean, ws.AliveHosts) //nolint:errcheck
	return n, nil
}

func runAlterx(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	if !FileExists(ws.AliveHosts) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()

	// Generate permutations
	permsFile := filepath.Join(ws.Recon, "alterx_perms.txt")
	_, err := runCmd(tctx, permsFile, FindTool("alterx"), "-silent", "-l", ws.AliveHosts)
	if err != nil || !FileExists(permsFile) {
		return 0, nil
	}

	// Resolve new permutations via dnsx and append to alive hosts
	resolvedFile := filepath.Join(ws.Recon, "alterx_resolved.txt")
	n, err := runCmd(tctx, resolvedFile,
		FindTool("dnsx"), "-silent", "-l", permsFile, "-a", "-threads", fmt.Sprintf("%d", cfg.Threads))
	if err != nil || n == 0 {
		return 0, nil
	}

	// Merge resolved alterx hosts into alive_hosts
	merged, _ := MergeDedup(ws.AliveHosts, ws.AliveHosts, resolvedFile)
	return merged, nil
}

// ─── Stage 3: Service Mapping ─────────────────────────────────────────────────

func runNaabu(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	if !FileExists(ws.AliveHosts) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.OpenPorts,
		FindTool("naabu"), "-silent", "-l", ws.AliveHosts,
		"-top-ports", "1000", "-threads", fmt.Sprintf("%d", cfg.Threads))
}

func runHttpx(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	if !FileExists(ws.AliveHosts) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()

	n, err := runCmd(tctx, ws.LiveWeb,
		FindTool("httpx"), "-silent", "-l", ws.AliveHosts,
		"-title", "-tech-detect", "-status-code", "-follow-redirects",
		"-threads", fmt.Sprintf("%d", cfg.Threads))
	if err != nil {
		return 0, err
	}

	// Extract clean URLs for downstream use
	urlsFile := filepath.Join(ws.Recon, "live_urls.txt")
	filterLines(ws.LiveWeb, urlsFile, func(line string) string { //nolint:errcheck
		parts := strings.Fields(line)
		if len(parts) > 0 && (strings.HasPrefix(parts[0], "http://") || strings.HasPrefix(parts[0], "https://")) {
			return parts[0]
		}
		return ""
	})
	return n, nil
}

func runTlsx(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	if !FileExists(ws.AliveHosts) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.TLSInfo,
		FindTool("tlsx"), "-silent", "-l", ws.AliveHosts, "-cn", "-san")
}

// ─── Stage 4: Content Discovery ───────────────────────────────────────────────

func runGau(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.HistoricalURLs,
		FindTool("gau"), "--threads", fmt.Sprintf("%d", cfg.Threads), "--subs", cfg.Target)
}

func runKatana(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	liveURLs := filepath.Join(ws.Recon, "live_urls.txt")
	if !FileExists(liveURLs) {
		if !FileExists(ws.LiveWeb) {
			return 0, nil
		}
		liveURLs = ws.LiveWeb
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.CrawledURLs,
		FindTool("katana"), "-silent", "-l", liveURLs,
		"-depth", "3", "-js-crawl", "-known-files", "all",
		"-concurrency", fmt.Sprintf("%d", cfg.Threads))
}

func runGetJS(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	liveURLs := filepath.Join(ws.Recon, "live_urls.txt")
	if !FileExists(liveURLs) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()

	// getJS reads URLs from file and finds .js files
	n, err := runCmd(tctx, ws.JSFiles,
		FindTool("getJS"), "-input", liveURLs, "--complete")
	if err != nil {
		// fallback: grep .js lines from crawled URLs
		if FileExists(ws.CrawledURLs) {
			filterLines(ws.CrawledURLs, ws.JSFiles, func(line string) string { //nolint:errcheck
				if strings.HasSuffix(strings.ToLower(strings.Split(line, "?")[0]), ".js") {
					return line
				}
				return ""
			})
			return CountLines(ws.JSFiles), nil
		}
	}
	return n, err
}

func runFfuf(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	liveURLs := filepath.Join(ws.Recon, "live_urls.txt")
	if !FileExists(liveURLs) {
		return 0, nil
	}

	wordlist := filepath.Join(FindSecLists(), "Discovery", "Web-Content", "raft-medium-directories.txt")
	if !FileExists(wordlist) {
		wordlist = filepath.Join(FindSecLists(), "Discovery", "Web-Content", "common.txt")
		if !FileExists(wordlist) {
			return 0, nil
		}
	}

	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()

	outFile := ws.Dirs
	// ffuf doesn't have a simple "one URL at a time" mode for list inputs
	// We run it against the target root for directory discovery
	targetURL := fmt.Sprintf("https://%s/FUZZ", cfg.Target)
	return runCmd(tctx, outFile,
		FindTool("ffuf"), "-s",
		"-w", wordlist,
		"-u", targetURL,
		"-mc", "200,301,302,403",
		"-t", fmt.Sprintf("%d", cfg.Threads))
}

// ─── Stage 5: Vulnerability Analysis ─────────────────────────────────────────

func runNuclei(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	liveURLs := filepath.Join(ws.Recon, "live_urls.txt")
	if !FileExists(liveURLs) {
		liveURLs = ws.LiveWeb
	}
	if !FileExists(liveURLs) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.NucleiHits,
		FindTool("nuclei"), "-silent", "-l", liveURLs,
		"-severity", "low,medium,high,critical",
		"-c", fmt.Sprintf("%d", cfg.Threads))
}

func runNucleiJS(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	if !FileExists(ws.JSFiles) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()

	outFile := filepath.Join(ws.Vulns, "js_secrets.txt")
	return runCmd(tctx, outFile,
		FindTool("nuclei"), "-silent", "-l", ws.JSFiles,
		"-tags", "exposure,token,config,secret")
}

func runDalfox(ctx context.Context, cfg *Config, ws *Workspace) (int, error) {
	if !FileExists(ws.AllURLs) {
		return 0, nil
	}
	tctx, cancel := withTimeout(ctx, cfg)
	defer cancel()
	return runCmd(tctx, ws.XSSHits,
		FindTool("dalfox"), "file", ws.AllURLs,
		"--silence", "--no-spinner", "--skip-bav")
}
