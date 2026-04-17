package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/pbnjay/memory"
	"github.com/pterm/pterm"
)

const ollamaBase = "http://localhost:11434"

// SelectAIModel returns the best Ollama model name for the current hardware.
func SelectAIModel() string {
	totalMB := memory.TotalMemory() / (1024 * 1024)

	switch {
	case totalMB < 4096:
		return "qwen2.5:0.5b"
	case totalMB < 8192:
		return "phi3.5"
	case totalMB < 16384:
		return "llama3.2:3b"
	default:
		return "llama3.1:8b"
	}
}

// OllamaAvailable returns true if the Ollama daemon is reachable.
func OllamaAvailable() bool {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(ollamaBase + "/api/tags")
	if err != nil {
		return false
	}
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

type ollamaRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type ollamaResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

// OllamaGenerate sends a prompt to the local Ollama instance and returns the response.
func OllamaGenerate(model, prompt string) (string, error) {
	payload, _ := json.Marshal(ollamaRequest{
		Model:  model,
		Prompt: prompt,
		Stream: false,
	})

	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Post(ollamaBase+"/api/generate", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var result ollamaResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}
	return result.Response, nil
}

// AITriage runs an AI analysis over the scan findings and appends to the report.
func AITriage(ws *Workspace, target string, reportPath string) {
	if !OllamaAvailable() {
		pterm.Warning.Println("Ollama not running — skipping AI triage. Start with: ollama serve")
		return
	}

	totalMB := memory.TotalMemory() / (1024 * 1024)
	model := SelectAIModel()
	pterm.Info.Printf("AI triage using %s (system RAM: %d MB)\n", model, totalMB)

	// Collect top findings for the prompt
	findings := collectTopFindings(ws)
	if len(findings) == 0 {
		pterm.Info.Println("No significant findings to triage.")
		return
	}

	prompt := buildTriagePrompt(target, findings)

	spinner, _ := pterm.DefaultSpinner.Start("AI analyzing findings...")
	response, err := OllamaGenerate(model, prompt)
	if err != nil {
		spinner.Fail(fmt.Sprintf("AI triage failed: %v", err))
		return
	}
	spinner.Success("AI triage complete")

	// Append AI section to report
	aiSection := fmt.Sprintf("\n\n## AI Security Triage\n\n**Model:** %s  \n**Date:** %s\n\n%s\n",
		model, time.Now().Format("2006-01-02 15:04"), response)

	f, err := os.OpenFile(reportPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		f.WriteString(aiSection) //nolint:errcheck
		f.Close()
	}

	pterm.Success.Printf("AI analysis appended to: %s\n", reportPath)
}

func collectTopFindings(ws *Workspace) []string {
	var findings []string

	// High-value: nuclei hits (first 20)
	if lines := readFirstN(ws.NucleiHits, 20); len(lines) > 0 {
		findings = append(findings, "=== Nuclei Vulnerability Hits ===")
		findings = append(findings, lines...)
	}

	// Secrets
	if lines := readFirstN(ws.Secrets, 10); len(lines) > 0 {
		findings = append(findings, "\n=== Secrets / Exposed Tokens ===")
		findings = append(findings, lines...)
	}

	// XSS
	if lines := readFirstN(ws.XSSHits, 10); len(lines) > 0 {
		findings = append(findings, "\n=== XSS Findings ===")
		findings = append(findings, lines...)
	}

	// Stats
	findings = append(findings, "\n=== Stats ===")
	findings = append(findings, fmt.Sprintf("Subdomains: %d", CountLines(ws.RawSubdomains)))
	findings = append(findings, fmt.Sprintf("Alive Hosts: %d", CountLines(ws.AliveHosts)))
	findings = append(findings, fmt.Sprintf("Web Services: %d", CountLines(ws.LiveWeb)))
	findings = append(findings, fmt.Sprintf("Total URLs: %d", CountLines(ws.AllURLs)))

	return findings
}

func buildTriagePrompt(target string, findings []string) string {
	data := strings.Join(findings, "\n")
	return fmt.Sprintf(`You are a professional bug bounty hunter and penetration tester.
Analyze the following reconnaissance findings for target: %s

%s

Provide:
1. A brief executive summary (2-3 sentences)
2. The top 3 most critical findings to investigate first, with reasoning
3. Specific attack vectors or follow-up actions for each critical finding
4. Quick wins (easy vulnerabilities to confirm)

Be concise and technical. Focus on actionable insights.`, target, data)
}

func readFirstN(path string, n int) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() && len(lines) < n {
		line := strings.TrimSpace(sc.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}
