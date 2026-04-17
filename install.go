package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pterm/pterm"
)

// toolManifest maps tool names to their go install paths.
var toolManifest = map[string]string{
	// Core pipeline tools
	"subfinder":   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
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

	// Utility tools
	"anew":        "github.com/tomnomnom/anew@latest",
	"unfurl":      "github.com/tomnomnom/unfurl@latest",
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
	"trufflehog":  "github.com/trufflesecurity/trufflehog/v3@latest",
	"subjs":       "github.com/lc/subjs@latest",
}

// RunInstaller installs or updates all tools in the manifest.
func RunInstaller() {
	printBanner()
	pterm.DefaultHeader.WithFullWidth().
		Printf(" OSCAR Installer — %d tools ", len(toolManifest))
	fmt.Println()

	// Install Go tools (parallel, max 4 at a time)
	installGoTools()

	// Clone SecLists
	installSecLists()

	// Update Nuclei templates
	updateNucleiTemplates()

	// Check Ollama
	checkOllama()

	fmt.Println()
	pterm.Success.Println("Installation complete. Run 'oscar -t <target>' to start scanning.")
}

func installGoTools() {
	pterm.DefaultSection.Println("Installing Go Tools")

	type result struct {
		name string
		err  error
	}

	jobs := make(chan struct{ name, path string }, len(toolManifest))
	results := make(chan result, len(toolManifest))

	// Worker pool with 4 concurrent installs
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				cmd := exec.Command("go", "install", "-v", job.path)
				cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
				err := cmd.Run()
				results <- result{name: job.name, err: err}
			}
		}()
	}

	for name, path := range toolManifest {
		jobs <- struct{ name, path string }{name, path}
	}
	close(jobs)

	go func() {
		wg.Wait()
		close(results)
	}()

	success, failed := 0, 0
	for r := range results {
		if r.err != nil {
			pterm.Warning.Printf("  %-20s  ✗ failed\n", r.name)
			failed++
		} else {
			pterm.FgGreen.Printf("  %-20s  ✓\n", r.name)
			success++
		}
	}

	fmt.Printf("\n  %d installed, %d failed\n", success, failed)
}

func installSecLists() {
	pterm.DefaultSection.Println("SecLists Wordlists")
	secPath := FindSecLists()

	if _, err := os.Stat(secPath); err == nil {
		pterm.Success.Printf("SecLists found at: %s\n", secPath)
		return
	}

	pterm.Info.Printf("Cloning SecLists to %s (this may take a while)...\n", secPath)
	spinner, _ := pterm.DefaultSpinner.Start("Cloning SecLists...")

	cmd := exec.Command("git", "clone", "--depth=1",
		"https://github.com/danielmiessler/SecLists.git", secPath)
	if err := cmd.Run(); err != nil {
		spinner.Fail(fmt.Sprintf("SecLists clone failed: %v", err))
		pterm.Info.Println("Install manually: git clone https://github.com/danielmiessler/SecLists.git ~/SecLists")
		return
	}
	spinner.Success(fmt.Sprintf("SecLists installed at: %s", secPath))
}

func updateNucleiTemplates() {
	pterm.DefaultSection.Println("Nuclei Templates")

	if _, err := exec.LookPath(FindTool("nuclei")); err != nil {
		pterm.Warning.Println("nuclei not found — skipping template update")
		return
	}

	spinner, _ := pterm.DefaultSpinner.Start("Updating Nuclei templates...")
	cmd := exec.Command(FindTool("nuclei"), "-update-templates")
	if err := cmd.Run(); err != nil {
		spinner.Warning("Nuclei template update failed (non-fatal)")
		return
	}
	spinner.Success("Nuclei templates updated")
}

func checkOllama() {
	pterm.DefaultSection.Println("AI Engine (Ollama)")

	if _, err := exec.LookPath("ollama"); err != nil {
		pterm.Info.Println("Ollama not found. Install from https://ollama.com for AI-powered reporting.")
		pterm.Info.Println("  Quick install: curl -fsSL https://ollama.com/install.sh | sh")
		return
	}

	model := SelectAIModel()
	pterm.Info.Printf("Optimal model for your hardware: %s\n", model)

	// Check if model is already pulled
	cmd := exec.Command("ollama", "list")
	out, _ := cmd.Output()
	if strings.Contains(string(out), strings.Split(model, ":")[0]) {
		pterm.Success.Printf("Model %s is already available\n", model)
		return
	}

	spinner, _ := pterm.DefaultSpinner.Start(fmt.Sprintf("Pulling %s (this may take a while)...", model))
	pullCmd := exec.Command("ollama", "pull", model)
	if err := pullCmd.Run(); err != nil {
		spinner.Warning(fmt.Sprintf("Could not pull %s: %v", model, err))
		return
	}
	spinner.Success(fmt.Sprintf("Model %s ready", model))
}

// printMCPConfig outputs the MCP configuration for Claude/Cursor integration.
func printMCPConfig() {
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	oscarBin := filepath.Join(gopath, "bin", "oscar")
	if _, err := os.Stat(oscarBin); err != nil {
		oscarBin = "oscar"
	}

	pterm.DefaultHeader.WithFullWidth().Println(" OSCAR MCP Configuration ")
	fmt.Println()
	pterm.Info.Println("Add this to your claude_desktop_config.json or Cursor settings:")
	fmt.Println()
	fmt.Printf(`{
  "mcpServers": {
    "oscar": {
      "command": "%s",
      "args": ["--mcp"]
    }
  }
}
`, oscarBin)
}
