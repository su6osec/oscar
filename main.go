package main

import (
	"bufio"
	"crypto/tls"
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

// ANSI color codes for pretty CLI
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
	InputFile   string
}

type Result struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	ContentLen int64
}

func main() {
	// Setup flags (short options)
	var config Config
	flag.IntVar(&config.Concurrency, "c", 50, "Concurrency level (number of workers)")
	flag.IntVar(&config.Timeout, "t", 5, "Timeout in seconds")
	flag.BoolVar(&config.Silent, "s", false, "Silent mode (only output live URLs)")
	flag.BoolVar(&config.Follow, "r", false, "Follow redirects")
	flag.StringVar(&config.InputFile, "f", "", "Input file with domains (default: stdin)")

	// Custom usage string
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%sOSCAR - Open-Source Cyber Attack Reconnaissance%s\n", Cyan, Reset)
		fmt.Fprintf(os.Stderr, "A blazing fast HTTP probing and reconnaissance tool.\n\n")
		fmt.Fprintf(os.Stderr, "Usage: oscar [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  cat domains.txt | oscar -c 100\n")
		fmt.Fprintf(os.Stderr, "  oscar -f targets.txt -s\n")
	}

	flag.Parse()

	if !config.Silent {
		fmt.Fprintf(os.Stderr, "%s[%s*%s]%s Starting OSCAR reconnaissance engine...\n", Blue, Reset, Blue, Reset)
	}

	targets := make(chan string)
	var wg sync.WaitGroup

	// Setup custom HTTP client
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

	// Start workers
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targets {
				probe(client, target, &config)
			}
		}()
	}

	// Read input
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
		// Read from stdin
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			// Not piped
			flag.Usage()
			os.Exit(0)
		}
		scanner = bufio.NewScanner(os.Stdin)
	}

	// Feed workers
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

// titleRegex captures the text inside <title> tags
var titleRegex = regexp.MustCompile(`(?i)<title>(.*?)</title>`)

func probe(client *http.Client, url string, config *Config) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "OSCAR Recon Engine / 1.0")

	// Pre-make the request to avoid keeping headers entirely in memory for long
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	res := Result{
		URL:        url,
		StatusCode: resp.StatusCode,
		Server:     resp.Header.Get("Server"),
	}

	// Read up to 10KB of body to extract the title
	body := make([]byte, 10240)
	n, _ := io.ReadFull(resp.Body, body)
	res.ContentLen = int64(n)

	matches := titleRegex.FindSubmatch(body)
	if len(matches) > 1 {
		res.Title = strings.TrimSpace(string(matches[1]))
	}

	displayResult(res, config)
}

func displayResult(res Result, config *Config) {
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

	fmt.Printf("%-35s [%s%d%s] [%s%-35s%s] [%s%-20s%s]\n",
		res.URL,
		statusColor, res.StatusCode, Reset,
		Cyan, title, Reset,
		Purple, server, Reset)
}
