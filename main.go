package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Cyan   = "\033[36m"
	Purple = "\033[35m"
)

type Config struct {
	Concurrency int
	Timeout     int
	Silent      bool
	Follow      bool
	JSONOut     bool
	VulnScan    bool
	InputFile   string
}

type Result struct {
	URL        string   `json:"url"`
	StatusCode int      `json:"status_code"`
	Title      string   `json:"title"`
	Server     string   `json:"server"`
	Tech       []string `json:"tech"`
	Vulns      []string `json:"vulns,omitempty"`
	ContentLen int64    `json:"content_length"`
}

func main() {
	var config Config
	flag.IntVar(&config.Concurrency, "c", 50, "Concurrency level (number of workers)")
	flag.IntVar(&config.Timeout, "t", 5, "Timeout in seconds")
	flag.BoolVar(&config.Silent, "s", false, "Silent mode (only output live URLs)")
	flag.BoolVar(&config.Follow, "r", false, "Follow redirects")
	flag.BoolVar(&config.JSONOut, "j", false, "Output results in JSONL format")
	flag.BoolVar(&config.VulnScan, "x", false, "Run lite vulnerability checks (.env, .git)")
	flag.StringVar(&config.InputFile, "f", "", "Input file with domains (default: stdin)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sOSCAR - Open-Source Cyber Attack Reconnaissance%s\n", Cyan, Reset)
		fmt.Fprintf(os.Stderr, "A blazing fast HTTP probing and reconnaissance tool.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: oscar [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  cat domains.txt | oscar -c 100 -x -j\n")
		fmt.Fprintf(os.Stderr, "  oscar -f targets.txt -s\n")
	}

	flag.Parse()

	if !config.Silent && !config.JSONOut {
		fmt.Fprintf(os.Stderr, "%s[%s*%s]%s Starting OSCAR reconnaissance engine...\n", Blue, Reset, Blue, Reset)
	}

	targets := make(chan string)
	var wg sync.WaitGroup

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(config.Timeout) * time.Second,
	}

	if !config.Follow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				probe(client, target, &config)
			}
		}()
	}

	var scanner *bufio.Scanner
	if config.InputFile != "" {
		file, err := os.Open(config.InputFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%sError reading file: %s%s\n", Red, err.Error(), Reset)
			os.Exit(1)
		}
		defer file.Close()
		scanner = bufio.NewScanner(file)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			flag.Usage()
			os.Exit(0)
		}
		scanner = bufio.NewScanner(os.Stdin)
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
				targets <- "https://" + line
				targets <- "http://" + line
			} else {
				targets <- line
			}
		}
	}

	close(targets)
	wg.Wait()
}

var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func probe(client *http.Client, url string, config *Config) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "OSCAR Recon Engine / 2.0")

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	res := Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
		Tech:       []string{},
		Vulns:      []string{},
	}

	if poweredBy := resp.Header.Get("X-Powered-By"); poweredBy != "" {
		res.Tech = append(res.Tech, poweredBy)
	}

	body := make([]byte, 15360)
	n, _ := io.ReadFull(resp.Body, body)
	res.ContentLen = int64(n)

	matches := titleRegex.FindSubmatch(body)
	if len(matches) > 1 {
		res.Title = strings.TrimSpace(string(matches[1]))
	}

	if config.VulnScan && res.StatusCode >= 200 && res.StatusCode < 400 {
		runVulnChecks(client, url, &res)
	}

	displayResult(res, config)
}

func runVulnChecks(client *http.Client, base string, res *Result) {
	endpoints := map[string]string{
		"/.env":        "APP_ENV=",
		"/.git/config": "[core]",
	}

	parsedBase := strings.TrimRight(base, "/")
	for path, signature := range endpoints {
		req, err := http.NewRequest("GET", parsedBase+path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		
		if resp.StatusCode == 200 {
			bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
			if strings.Contains(string(bodyBytes), signature) {
				res.Vulns = append(res.Vulns, "EXPOSED"+path)
			}
		}
		resp.Body.Close()
	}
}

func displayResult(res Result, config *Config) {
	if config.JSONOut {
		data, _ := json.Marshal(res)
		fmt.Println(string(data))
		return
	}

	if config.Silent {
		fmt.Println(res.URL)
		return
	}

	statusColor := Green
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		statusColor = Yellow
	} else if res.StatusCode >= 400 {
		statusColor = Red
	}

	title := "N/A"
	if res.Title != "" {
		if len(res.Title) > 35 {
			title = res.Title[:32] + "..."
		} else {
			title = res.Title
		}
	}

	server := "Unknown"
	if res.Server != "" {
		if len(res.Server) > 20 {
			server = res.Server[:17] + "..."
		} else {
			server = res.Server
		}
	}

	extra := ""
	if len(res.Tech) > 0 {
		extra += fmt.Sprintf("[%v] ", res.Tech)
	}
	if len(res.Vulns) > 0 {
		extra += fmt.Sprintf("%s[VULN: %v]%s ", Red, res.Vulns, Reset)
	}

	fmt.Printf("%-35s [%s%d%s] [%s%-35s%s] [%s%-20s%s] %s\n",
		res.URL,
		statusColor, res.StatusCode, Reset,
		Cyan, title, Reset,
		Purple, server, Reset,
		extra)
}
