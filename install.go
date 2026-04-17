package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pbnjay/memory"
	"github.com/pterm/pterm"
)

// toolManifest maps tool names to their go install paths.
// trufflehog is handled separately (replace-directive issue).
var toolManifest = map[string]string{
	// Core pipeline
	"subfinder":  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
	"assetfinder": "github.com/tomnomnom/assetfinder@latest",
	"dnsx":        "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
	"alterx":      "github.com/projectdiscovery/alterx/cmd/alterx@latest",
	"naabu":       "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
	"httpx":       "github.com/projectdiscovery/httpx/cmd/httpx@latest",
	"tlsx":        "github.com/projectdiscovery/tlsx/cmd/tlsx@latest",
	"gau":         "github.com/lc/gau/v2/cmd/gau@latest",
	"katana":      "github.com/projectdiscovery/katana/cmd/katana@latest",
	"getJS":       "github.com/003random/getJS@latest",
	"ffuf":        "github.com/ffuf/ffuf/v2@latest",
	"nuclei":      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
	"dalfox":      "github.com/hahwul/dalfox/v2@latest",
	// Utilities
	"anew":       "github.com/tomnomnom/anew@latest",
	"unfurl":     "github.com/tomnomnom/unfurl@latest",
	"waybackurls": "github.com/tomnomnom/waybackurls@latest",
	"gf":          "github.com/tomnomnom/gf@latest",
	"qsreplace":   "github.com/tomnomnom/qsreplace@latest",
	"hakrawler":   "github.com/hakluke/hakrawler@latest",
	"gospider":    "github.com/jaeles-project/gospider@latest",
	"gowitness":   "github.com/sensepost/gowitness@latest",
	"crlfuzz":     "github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
	"shuffledns":  "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest",
	"puredns":     "github.com/d3mondev/puredns/v2@latest",
	"cdncheck":    "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest",
	"mapcidr":     "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest",
	"asnmap":      "github.com/projectdiscovery/asnmap/cmd/asnmap@latest",
	"notify":      "github.com/projectdiscovery/notify/cmd/notify@latest",
	"uncover":     "github.com/projectdiscovery/uncover/cmd/uncover@latest",
	"subjs":       "github.com/lc/subjs@latest",
}

// RunInstaller installs or updates all tools.
// Note: printBanner() is already called by main() before this.
func RunInstaller() {
	total := len(toolManifest) + 1 // +1 for trufflehog
	pterm.DefaultHeader.WithFullWidth().
		Printf("  OSCAR Tool Installer  ·  %d tools  ", total)
	fmt.Println()

	installGoTools()
	installTrufflehog()
	installSecLists()
	updateNucleiTemplates()
	checkOllama()

	fmt.Println()
	pterm.DefaultBox.
		WithTitle("Done").
		WithTitleTopCenter().
		Println("All done!  Run:  " + pterm.FgLightCyan.Sprint("oscar -t <target>"))
}

// ─── Go tools ─────────────────────────────────────────────────────────────────

func installGoTools() {
	pterm.DefaultSection.Println("Go Tools")

	// Sorted names for deterministic display
	names := make([]string, 0, len(toolManifest))
	for name := range toolManifest {
		names = append(names, name)
	}
	sort.Strings(names)

	// Progress bar
	pb, _ := pterm.DefaultProgressbar.
		WithTotal(len(names)).
		WithTitle("  Installing").
		WithRemoveWhenDone(true).
		Start()

	type result struct {
		name string
		err  error
	}

	jobs := make(chan struct{ name, path string }, len(toolManifest))
	results := make(chan result, len(toolManifest))

	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				cmd := exec.Command("go", "install", job.path)
				var stderr bytes.Buffer
				cmd.Stderr = &stderr
				err := cmd.Run()
				results <- result{name: job.name, err: err}
			}
		}()
	}

	for _, name := range names {
		jobs <- struct{ name, path string }{name, toolManifest[name]}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect all results
	resultMap := make(map[string]error)
	for r := range results {
		resultMap[r.name] = r.err
		pb.Increment()
	}
	pb.Stop()

	// Display in a 3-column grid, sorted
	var failed []string
	colW := 20
	cols := 3
	for i, name := range names {
		if resultMap[name] == nil {
			fmt.Printf("  %s%-*s", pterm.FgGreen.Sprint("✓ "), colW, name)
		} else {
			fmt.Printf("  %s%-*s", pterm.FgRed.Sprint("✗ "), colW, name)
			failed = append(failed, name)
		}
		if (i+1)%cols == 0 || i == len(names)-1 {
			fmt.Println()
		}
	}

	fmt.Println()
	if len(failed) > 0 {
		pterm.Warning.Printf("Failed (%d): %s\n", len(failed), strings.Join(failed, ", "))
		pterm.Info.Println("Re-run 'oscar -up' to retry, or install manually with 'go install <path>'")
	} else {
		pterm.Success.Printf("All %d Go tools installed\n", len(names))
	}
}

// ─── Trufflehog (special case) ────────────────────────────────────────────────

func installTrufflehog() {
	pterm.DefaultSection.Println("Trufflehog (Secret Scanner)")

	if _, err := exec.LookPath("trufflehog"); err == nil {
		pterm.Success.Println("trufflehog already installed")
		return
	}

	// trufflehog can't be installed via `go install` (replace directives in go.mod).
	// Use the official install script instead.
	pterm.Info.Println("Installing via official install script...")

	spinner, _ := pterm.DefaultSpinner.
		WithRemoveWhenDone(false).
		Start("Downloading trufflehog...")

	resp, err := http.Get("https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh")
	if err != nil {
		spinner.Fail("Download failed — install manually:")
		fmt.Println("  curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin")
		return
	}
	defer resp.Body.Close()

	// Run: curl … | sh -s -- -b /usr/local/bin
	curlCmd := exec.Command("curl", "-sSfL",
		"https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh")
	shCmd := exec.Command("sh", "-s", "--", "-b", "/usr/local/bin")

	pipe, _ := curlCmd.StdoutPipe()
	shCmd.Stdin = pipe
	shCmd.Stdout = os.Stdout
	shCmd.Stderr = os.Stderr

	_ = curlCmd.Start()
	_ = shCmd.Start()
	_ = curlCmd.Wait()

	if err := shCmd.Wait(); err != nil {
		spinner.Fail(fmt.Sprintf("trufflehog install failed: %v", err))
		return
	}
	spinner.Success("trufflehog installed")
}

// ─── SecLists ─────────────────────────────────────────────────────────────────

func installSecLists() {
	pterm.DefaultSection.Println("SecLists Wordlists")
	secPath := FindSecLists()

	if info, err := os.Stat(secPath); err == nil && info.IsDir() {
		pterm.Success.Printf("Already present: %s\n", secPath)
		return
	}

	pterm.Info.Printf("Cloning to %s  (this may take a few minutes)...\n", secPath)
	spinner, _ := pterm.DefaultSpinner.
		WithRemoveWhenDone(false).
		Start("Cloning SecLists")

	cmd := exec.Command("git", "clone", "--depth=1",
		"https://github.com/danielmiessler/SecLists.git", secPath)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Run(); err != nil {
		spinner.Fail("Clone failed")
		fmt.Printf("  Manual install: git clone --depth=1 https://github.com/danielmiessler/SecLists.git %s\n", secPath)
		return
	}
	spinner.Success(fmt.Sprintf("SecLists ready at %s", secPath))
}

// ─── Nuclei templates ─────────────────────────────────────────────────────────

func updateNucleiTemplates() {
	pterm.DefaultSection.Println("Nuclei Templates")

	nucleiBin := FindTool("nuclei")
	if _, err := exec.LookPath(nucleiBin); err != nil {
		pterm.Warning.Println("nuclei not found — skipping template update")
		return
	}

	pterm.Info.Print("Updating templates...  ")
	cmd := exec.Command(nucleiBin, "-update-templates", "-disable-update-check")
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Run(); err != nil {
		pterm.FgYellow.Println("update failed (non-fatal)")
		return
	}
	pterm.FgGreen.Println("✓ done")
}

// ─── Ollama / AI engine ───────────────────────────────────────────────────────

func checkOllama() {
	pterm.DefaultSection.Println("AI Engine (Ollama)")

	ollamaPath, err := exec.LookPath("ollama")
	if err != nil {
		pterm.Warning.Println("Ollama is not installed.")
		pterm.Info.Println("  Install:  curl -fsSL https://ollama.com/install.sh | sh")
		pterm.Info.Println("  Then re-run 'oscar -up' to pull the optimal model.")
		return
	}
	pterm.FgGray.Printf("  Found: %s\n", ollamaPath)

	model := SelectAIModel()
	ramMB := memory.TotalMemory() / (1024 * 1024)
	pterm.Info.Printf("  System RAM: ~%d MB  →  optimal model: %s\n", ramMB, pterm.FgLightCyan.Sprint(model))

	// Check daemon
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err != nil {
		pterm.Warning.Println("  Ollama daemon is not running — model check skipped.")
		pterm.Info.Println("  Start daemon:  ollama serve")
		pterm.Info.Printf("  Pull model:    ollama pull %s\n", model)
		return
	}
	resp.Body.Close()

	if ollamaModelInstalled(model) {
		pterm.Success.Printf("  Model %s is already installed — nothing to do.\n", model)
		return
	}

	pterm.Info.Printf("  Pulling %s  (may take a few minutes)...\n", model)
	pullCmd := exec.Command("ollama", "pull", model)
	pullCmd.Stdout = os.Stdout
	pullCmd.Stderr = os.Stderr
	if err := pullCmd.Run(); err != nil {
		pterm.Warning.Printf("  Pull failed: %v\n", err)
		pterm.Info.Printf("  Retry manually: ollama pull %s\n", model)
		return
	}
	pterm.Success.Printf("  Model %s ready.\n", model)
}

// ollamaModelInstalled returns true if the given model tag is already present.
// It checks exact tag first, then falls back to base-name matching so that
// e.g. "phi3.5:latest" satisfies a request for "phi3.5:mini".
func ollamaModelInstalled(model string) bool {
	out, err := exec.Command("ollama", "list").Output()
	if err != nil {
		return false
	}
	list := string(out)
	// Exact match first
	if strings.Contains(list, model) {
		return true
	}
	// Base-name fallback: "phi3.5:mini" → look for "phi3.5"
	base := strings.SplitN(model, ":", 2)[0]
	for _, line := range strings.Split(list, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if strings.HasPrefix(fields[0], base+":") || fields[0] == base {
			return true
		}
	}
	return false
}

// ─── Agent / MCP config ───────────────────────────────────────────────────────

// aiToolConfig describes a known AI tool's MCP config file location.
type aiToolConfig struct {
	Name string
	Path string
}

// knownAIConfigs returns the hardcoded list of well-known AI tool config paths.
func knownAIConfigs() []aiToolConfig {
	home, _ := os.UserHomeDir()
	return []aiToolConfig{
		// Claude CLI (claude-code, the terminal agent)
		{Name: "Claude CLI", Path: filepath.Join(home, ".claude", "settings.json")},
		// Claude Desktop app
		{Name: "Claude Desktop", Path: filepath.Join(home, ".config", "claude", "claude_desktop_config.json")},
		{Name: "Claude Desktop (Windows)", Path: filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")},
		// Editors / AI tools
		{Name: "Cursor", Path: filepath.Join(home, ".cursor", "mcp.json")},
		{Name: "Windsurf", Path: filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")},
		{Name: "VS Code (Cline/Roo)", Path: filepath.Join(home, ".vscode", "mcp.json")},
		{Name: "Zed", Path: filepath.Join(home, ".config", "zed", "settings.json")},
		{Name: "Continue", Path: filepath.Join(home, ".continue", "config.json")},
	}
}

// ── Patterns used by the dynamic scanner ─────────────────────────────────────

// mcpFileRe matches JSON filenames that are likely MCP / AI tool config files.
var mcpFileRe = regexp.MustCompile(`(?i)^(settings|mcp[_-]?config|claude[_-]?desktop[_-]?config|mcp|config)\.json$`)

// aiDirRe matches directory names that belong to an AI coding tool.
var aiDirRe = regexp.MustCompile(`(?i)(claude|cursor|windsurf|codeium|zed|copilot|cline|continue|aider|cody|tabnine|ghostwriter|supermaven|openai|anthropic|gemini)`)

// inferToolLabel converts a lowercase file path into a human-readable tool name.
func inferToolLabel(lpath string) string {
	switch {
	case strings.Contains(lpath, ".claude"):
		return "Claude CLI"
	case strings.Contains(lpath, "claude"):
		return "Claude Desktop"
	case strings.Contains(lpath, "cursor"):
		return "Cursor"
	case strings.Contains(lpath, "windsurf") || strings.Contains(lpath, "codeium"):
		return "Windsurf"
	case strings.Contains(lpath, "zed"):
		return "Zed"
	case strings.Contains(lpath, "continue"):
		return "Continue"
	case strings.Contains(lpath, "cline"):
		return "Cline"
	case strings.Contains(lpath, "copilot"):
		return "GitHub Copilot"
	case strings.Contains(lpath, "aider"):
		return "Aider"
	case strings.Contains(lpath, "cody"):
		return "Sourcegraph Cody"
	case strings.Contains(lpath, "tabnine"):
		return "Tabnine"
	default:
		return ""
	}
}

// discoverAIConfigs scans home dotdirs and ~/.config/* up to depth 2 for JSON
// files that look like AI tool MCP configs. This catches tools whose paths are
// not in the hardcoded list — e.g. new CLI tools installed to ~/.someai/.
func discoverAIConfigs(known map[string]bool) []aiToolConfig {
	home, _ := os.UserHomeDir()
	var found []aiToolConfig

	// Roots to scan: ~/.config/* and ~/.<dotdir>/*
	scanRoots := func(root string, onlyDots bool) {
		entries, err := os.ReadDir(root)
		if err != nil {
			return
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			name := entry.Name()
			if onlyDots && !strings.HasPrefix(name, ".") {
				continue
			}
			// Only descend into AI-related directories
			if !aiDirRe.MatchString(name) {
				continue
			}
			dirPath := filepath.Join(root, name)
			// Walk up to depth 2 inside this dir
			scanDir(dirPath, 2, func(path string) {
				base := filepath.Base(path)
				if !mcpFileRe.MatchString(base) {
					return
				}
				if known[path] {
					return // already in hardcoded list
				}
				label := inferToolLabel(strings.ToLower(path))
				if label == "" {
					label = strings.Trim(name, ".")
				}
				found = append(found, aiToolConfig{
					Name: label + " (auto-detected)",
					Path: path,
				})
				known[path] = true
			})
		}
	}

	scanRoots(home, true)                              // ~/.*
	scanRoots(filepath.Join(home, ".config"), false)   // ~/.config/*

	return found
}

// scanDir walks a directory up to maxDepth levels, calling fn for each file.
func scanDir(root string, maxDepth int, fn func(string)) {
	if maxDepth < 0 {
		return
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, e := range entries {
		full := filepath.Join(root, e.Name())
		if e.IsDir() {
			scanDir(full, maxDepth-1, fn)
		} else {
			fn(full)
		}
	}
}

// printAgentSetup detects installed AI tools and provides targeted, auto-patch
// MCP configuration instructions for each.
func printAgentSetup() {
	oscarBin := resolveOscarBinary()

	pterm.DefaultHeader.WithFullWidth().Println("  OSCAR  ·  Agentic MCP Setup  ")
	fmt.Println()

	// ── Step 1: binary path ──────────────────────────────────────────────────
	pterm.DefaultSection.Println("Step 1 — OSCAR binary location")
	fmt.Printf("  %s\n\n", pterm.FgLightCyan.Sprint(oscarBin))

	// ── Step 2: MCP JSON snippet ─────────────────────────────────────────────
	pterm.DefaultSection.Println("Step 2 — MCP configuration block")
	mcpSnippet := fmt.Sprintf(`{
  "mcpServers": {
    "oscar": {
      "command": "%s",
      "args": ["-mcp-server"]
    }
  }
}`, oscarBin)
	pterm.DefaultBox.WithTitle("JSON block to add / merge").Println(mcpSnippet)

	// ── Step 3: detect + patch ───────────────────────────────────────────────
	pterm.DefaultSection.Println("Step 3 — Detected AI tool config files")

	// Build set of known paths so the dynamic scanner can skip duplicates
	seenPaths := make(map[string]bool)
	var found, notFound []aiToolConfig

	for _, cfg := range knownAIConfigs() {
		seenPaths[cfg.Path] = true
		if _, err := os.Stat(cfg.Path); err == nil {
			found = append(found, cfg)
		} else {
			notFound = append(notFound, cfg)
		}
	}

	// Dynamic scan: find config files in AI-related dotdirs not in hardcoded list
	for _, cfg := range discoverAIConfigs(seenPaths) {
		if _, err := os.Stat(cfg.Path); err == nil {
			found = append(found, cfg)
		}
	}

	if len(found) == 0 {
		pterm.Warning.Println("No AI tool config files detected on this system.")
		fmt.Println()
		pterm.Info.Println("Known locations (create the file if missing):")
		for _, cfg := range notFound {
			fmt.Printf("  %-30s  %s\n", cfg.Name, pterm.FgGray.Sprint(cfg.Path))
		}
	} else {
		for _, cfg := range found {
			if configHasOscar(cfg.Path) {
				fmt.Printf("  %s  %-32s  %s\n",
					pterm.FgGreen.Sprint("✓ configured"),
					cfg.Name,
					pterm.FgGray.Sprint(cfg.Path))
			} else {
				fmt.Printf("  %s  %-32s  %s\n",
					pterm.FgYellow.Sprint("⚡ needs entry"),
					cfg.Name,
					pterm.FgGray.Sprint(cfg.Path))
			}
		}

		fmt.Println()
		patched := 0
		for _, cfg := range found {
			if configHasOscar(cfg.Path) {
				continue
			}
			if err := patchMCPConfig(cfg.Path, oscarBin); err != nil {
				pterm.Warning.Printf("  Auto-patch failed for %s: %v\n", cfg.Name, err)
				pterm.Info.Printf("  Add manually to: %s\n", cfg.Path)
			} else {
				pterm.Success.Printf("  Patched: %s\n", cfg.Path)
				patched++
			}
		}
		if patched > 0 {
			fmt.Println()
			pterm.Info.Println("Restart your AI app to load the new MCP server.")
		}
	}

	fmt.Println()
	pterm.Info.Printf("Docs: https://github.com/su6osec/oscar\n")
}

// configHasOscar returns true if the JSON file already contains an "oscar"
// entry under mcpServers.
func configHasOscar(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		// Not valid JSON yet — treat as unconfigured
		return false
	}
	servers, ok := cfg["mcpServers"].(map[string]any)
	if !ok {
		return false
	}
	_, exists := servers["oscar"]
	return exists
}

// patchMCPConfig merges the oscar MCP entry into an existing JSON config file.
// It creates the file (with an empty JSON object) if it doesn't exist yet.
func patchMCPConfig(path string, oscarBin string) error {
	// Read existing content (or start with an empty object)
	var cfg map[string]any
	data, err := os.ReadFile(path)
	if err != nil || len(bytes.TrimSpace(data)) == 0 {
		cfg = make(map[string]any)
	} else if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("existing config is not valid JSON: %w", err)
	}

	// Ensure mcpServers key exists
	servers, ok := cfg["mcpServers"].(map[string]any)
	if !ok {
		servers = make(map[string]any)
		cfg["mcpServers"] = servers
	}

	// Add oscar entry
	servers["oscar"] = map[string]any{
		"command": oscarBin,
		"args":    []string{"-mcp-server"},
	}

	// Ensure parent directory exists
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	out, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0644)
}

func resolveOscarBinary() string {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	candidate := filepath.Join(gopath, "bin", "oscar")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	if p, err := exec.LookPath("oscar"); err == nil {
		return p
	}
	return "oscar"
}
