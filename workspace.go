package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Workspace manages the directory structure and file paths for a scan.
type Workspace struct {
	Root    string
	Recon   string
	Content string
	Vulns   string
	JS      string
	Logs    string
	State   *ScanState

	// Stage 1 outputs (passive discovery)
	SubfinderOut    string
	AssetfinderOut  string
	CrtshOut        string
	RawSubdomains   string // merged + deduped

	// Stage 2 outputs (DNS resolution)
	AliveHosts string
	AliveIPs   string

	// Stage 3 outputs (service mapping)
	LiveWeb   string
	OpenPorts string
	TLSInfo   string

	// Stage 4 outputs (content discovery)
	HistoricalURLs string
	CrawledURLs    string
	AllURLs        string
	JSFiles        string

	// Stage 5 outputs (vulnerability analysis)
	NucleiHits string
	XSSHits    string
	Secrets    string
	Dirs       string
}

func NewWorkspace(target string) (*Workspace, error) {
	root := filepath.Join("reports", target)
	ws := &Workspace{
		Root:    root,
		Recon:   filepath.Join(root, "recon"),
		Content: filepath.Join(root, "content"),
		Vulns:   filepath.Join(root, "vulns"),
		JS:      filepath.Join(root, "javascript"),
		Logs:    filepath.Join(root, "logs"),
	}

	for _, d := range []string{ws.Recon, ws.Content, ws.Vulns, ws.JS, ws.Logs} {
		if err := os.MkdirAll(d, 0755); err != nil {
			return nil, fmt.Errorf("workspace: %w", err)
		}
	}

	ws.SubfinderOut    = filepath.Join(ws.Recon, "subfinder_out.txt")
	ws.AssetfinderOut  = filepath.Join(ws.Recon, "assetfinder_out.txt")
	ws.CrtshOut        = filepath.Join(ws.Recon, "crtsh_out.txt")
	ws.RawSubdomains   = filepath.Join(ws.Recon, "subdomains_raw.txt")
	ws.AliveHosts      = filepath.Join(ws.Recon, "subdomains_alive.txt")
	ws.AliveIPs        = filepath.Join(ws.Recon, "ips.txt")
	ws.LiveWeb         = filepath.Join(ws.Recon, "live_web.txt")
	ws.OpenPorts       = filepath.Join(ws.Recon, "open_ports.txt")
	ws.TLSInfo         = filepath.Join(ws.Recon, "tls_info.txt")
	ws.HistoricalURLs  = filepath.Join(ws.Content, "historical_urls.txt")
	ws.CrawledURLs     = filepath.Join(ws.Content, "crawled_urls.txt")
	ws.AllURLs         = filepath.Join(ws.Content, "all_urls.txt")
	ws.JSFiles         = filepath.Join(ws.Content, "js_files.txt")
	ws.NucleiHits      = filepath.Join(ws.Vulns, "nuclei_hits.txt")
	ws.XSSHits         = filepath.Join(ws.Vulns, "xss_hits.txt")
	ws.Secrets         = filepath.Join(ws.Vulns, "secrets.txt")
	ws.Dirs            = filepath.Join(ws.Content, "directories.txt")

	ws.State = NewScanState(filepath.Join(root, ".scan_state.json"))
	return ws, nil
}

// MergeDedup merges multiple source files into dst, deduplicating lines.
func MergeDedup(dst string, srcs ...string) (int, error) {
	seen := make(map[string]bool)
	var lines []string

	for _, src := range srcs {
		f, err := os.Open(src)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			line := strings.TrimSpace(strings.ToLower(sc.Text()))
			if line != "" && !seen[line] {
				seen[line] = true
				lines = append(lines, line)
			}
		}
		f.Close()
	}

	out := strings.Join(lines, "\n")
	if len(lines) > 0 {
		out += "\n"
	}
	return len(lines), os.WriteFile(dst, []byte(out), 0644)
}

// CountLines returns the number of non-empty lines in a file.
func CountLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

// FileExists returns true if the file exists and has content.
func FileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Size() > 0
}

// FindSecLists searches common installation paths for SecLists.
func FindSecLists() string {
	home, _ := os.UserHomeDir()
	paths := []string{
		"/usr/share/seclists",
		"/usr/share/wordlists/seclists",
		"/opt/SecLists",
		filepath.Join(home, "SecLists"),
		filepath.Join(home, "wordlists", "SecLists"),
	}
	for _, p := range paths {
		if info, err := os.Stat(p); err == nil && info.IsDir() {
			return p
		}
	}
	return filepath.Join(home, "SecLists")
}

// FindTool resolves a tool binary from PATH or GOPATH/bin.
func FindTool(name string) string {
	if path, err := exec.LookPath(name); err == nil {
		return path
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		home, _ := os.UserHomeDir()
		gopath = filepath.Join(home, "go")
	}
	return filepath.Join(gopath, "bin", name)
}
