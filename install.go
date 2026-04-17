package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
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

	// Detect optimal model
	model := SelectAIModel()
	ramMB := memory.TotalMemory() / (1024 * 1024)
	pterm.Info.Printf("  System RAM: ~%d MB  →  model: %s\n", ramMB, pterm.FgLightCyan.Sprint(model))

	// Check if daemon is reachable
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err != nil {
		pterm.Warning.Println("  Ollama daemon is not running.")
		pterm.Info.Println("  Start it:      ollama serve")
		pterm.Info.Printf("  Pull model:    ollama pull %s\n", model)
		return
	}
	resp.Body.Close()

	// Check if model already downloaded
	listOut, _ := exec.Command("ollama", "list").Output()
	modelBase := strings.Split(model, ":")[0]
	if strings.Contains(string(listOut), modelBase) {
		pterm.Success.Printf("  Model %s already downloaded\n", model)
		return
	}

	// Pull the model
	pterm.Info.Printf("  Pulling %s  (grab a coffee, this may take a while)...\n", model)
	pullCmd := exec.Command("ollama", "pull", model)
	pullCmd.Stdout = os.Stdout
	pullCmd.Stderr = os.Stderr
	if err := pullCmd.Run(); err != nil {
		pterm.Warning.Printf("  Pull failed: %v\n", err)
		pterm.Info.Printf("  Manual pull: ollama pull %s\n", model)
		return
	}
	pterm.Success.Printf("  Model %s ready\n", model)
}


// ─── Agent / MCP config ───────────────────────────────────────────────────────

// printAgentSetup prints clear, step-by-step MCP configuration instructions.
func printAgentSetup() {
	oscarBin := resolveOscarBinary()

	pterm.DefaultHeader.WithFullWidth().Println("  OSCAR  ·  Agentic MCP Setup  ")
	fmt.Println()

	pterm.DefaultSection.Println("Step 1 — Make sure OSCAR is in your PATH")
	fmt.Printf("  Binary location: %s\n\n", pterm.FgLightCyan.Sprint(oscarBin))

	pterm.DefaultSection.Println("Step 2 — Add this block to your AI tool config")

	config := fmt.Sprintf(`{
  "mcpServers": {
    "oscar": {
      "command": "%s",
      "args": ["-mcp-server"]
    }
  }
}`, oscarBin)

	pterm.DefaultBox.WithTitle("MCP Config JSON").Println(config)

	pterm.DefaultSection.Println("Step 3 — Config file locations")

	home, _ := os.UserHomeDir()

	locations := []struct{ label, path string }{
		{"Claude Desktop (Linux/Mac)", filepath.Join(home, ".config", "claude", "claude_desktop_config.json")},
		{"Claude Desktop (Windows)", filepath.Join(home, "AppData", "Roaming", "Claude", "claude_desktop_config.json")},
		{"Cursor", filepath.Join(home, ".cursor", "mcp.json")},
		{"Windsurf", filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")},
	}

	for _, loc := range locations {
		exists := ""
		if _, err := os.Stat(loc.path); err == nil {
			exists = pterm.FgGreen.Sprint(" ← exists")
		}
		fmt.Printf("  %-28s %s%s\n", loc.label, pterm.FgGray.Sprint(loc.path), exists)
	}

	fmt.Println()
	pterm.Info.Println("Paste the JSON above into the mcpServers section of whichever file applies, then restart your AI app.")
}

func resolveOscarBinary() string {
	// 1. Check GOPATH/bin/oscar
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	candidate := filepath.Join(gopath, "bin", "oscar")
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	// 2. Check PATH
	if p, err := exec.LookPath("oscar"); err == nil {
		return p
	}
	// 3. Fallback
	return "oscar"
}
