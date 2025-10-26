package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// --- ANSI Color Codes ---
const (
	colorGoldenBrown = "\033[38;2;138;116;10m"
	colorReset       = "\033[0m"
	colorRed         = "\033[31m"
	colorGreen       = "\033[32m"
	colorYellow      = "\033[33m"
	colorBlue        = "\033[34m"
)

// --- Flags ---
var (
	flagURL     = flag.String("u", "", "Scan a single URL (http[s]://...)")
	flagFile    = flag.String("f", "", "Scan a file (each line is a URL)")
	flagSecret  = flag.Bool("secret", false, "Detect secret patterns using regex")
	flagLinks   = flag.Bool("links", false, "Extract in-scope links (relative + absolute)")
	flagSubs    = flag.Bool("subs", false, "Extract only subdomains for the target's root domain")
	flagPath    = flag.Bool("path", false, "Extract file system paths (absolute, relative, home-relative)")
	flagCustom  = flag.String("custom", "", "Custom mode: comma-separated list (links,path,secret,subs)")
	flagOutfile = flag.String("o", "", "Save output to plain text file (optional)")
	flagTimeout = flag.Int("timeout", 10, "HTTP request timeout in seconds")
	flagThread  = flag.Int("thread", 5, "Number of concurrent threads")
	flagExclude = flag.String("exclude", "", "Comma-separated list of extensions to exclude (e.g. png,jpg,svg)")
	flagSilent  = flag.Bool("s", false, "Silent mode (hide banner and summary)")
	flagVerbose = flag.Bool("v", false, "Verbose mode (show detailed errors)")
	flagHelp    = flag.Bool("h", false, "Show help")
)

// --- Statistics ---
type Stats struct {
	Links      int64
	Paths      int64
	Subdomains int64
	Secrets    int64
	Errors     int64
	Processed  int64
}

var stats Stats

// --- Helper: expand ~ ---
func expandPath(p string) string {
	if strings.HasPrefix(p, "~") {
		usr, err := user.Current()
		if err == nil {
			return filepath.Join(usr.HomeDir, strings.TrimPrefix(p, "~"))
		}
	}
	return p
}

// --- Helper: root domain extraction ---
func getRootDomain(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	host := u.Hostname()
	parts := strings.Split(host, ".")
	if len(parts) >= 2 {
		return parts[len(parts)-2] + "." + parts[len(parts)-1]
	}
	return host
}

// --- Regex for ANSI color removal ---
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// --- Exclude logic ---
func shouldExclude(target string, excluded []string) bool {
	lower := strings.ToLower(target)
	for _, e := range excluded {
		if e == "" {
			continue
		}
		pattern := "." + strings.TrimPrefix(e, ".")
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// --- Link extraction regex ---
var linkRegex = regexp.MustCompile(`(?i)(?:href|src|url|action)\s*=\s*["']([^"'>\s]+)["']|fetch\(["']([^"']+)["']\)|import\s*\(["']([^"']+)["']\)`)

type linkItem struct {
	URL  string
	Type string
}

func extractLinks(content, base, rootDomain string, excludedExts []string) []linkItem {
	matches := linkRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var links []linkItem

	for _, m := range matches {
		link := ""
		if m[1] != "" {
			link = m[1]
		} else if len(m) > 2 && m[2] != "" {
			link = m[2]
		} else if len(m) > 3 && m[3] != "" {
			link = m[3]
		}
		if link == "" {
			continue
		}

		// Skip data URIs, javascript:, mailto:, etc.
		if strings.HasPrefix(link, "data:") || 
		   strings.HasPrefix(link, "javascript:") || 
		   strings.HasPrefix(link, "mailto:") ||
		   strings.HasPrefix(link, "tel:") {
			continue
		}

		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		baseURL, _ := url.Parse(base)
		full := baseURL.ResolveReference(u).String()

		if shouldExclude(full, excludedExts) {
			continue
		}

		linkType := "Relative"
		if u.IsAbs() {
			linkType = "Absolute"
		}

		if strings.Contains(full, rootDomain) && !seen[full] {
			seen[full] = true
			links = append(links, linkItem{URL: full, Type: linkType})
		}
	}
	return links
}

// --- Extract file system paths ---
var pathRegex = regexp.MustCompile(`(?m)(?:["'\s]|^)(~\/[^\s"'<>]+|\/[A-Za-z0-9._\-/]+|(?:\.\.?\/)[A-Za-z0-9._\-/]+)(?:["'\s]|$)`)

type pathItem struct {
	Path string
	Type string
}

func extractPaths(content string, excludedExts []string) []pathItem {
	matches := pathRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var paths []pathItem

	for _, m := range matches {
		p := strings.TrimSpace(m[1])
		if p == "" || seen[p] {
			continue
		}
		if shouldExclude(p, excludedExts) {
			continue
		}
		seen[p] = true

		pType := "Relative"
		if strings.HasPrefix(p, "/") {
			pType = "Absolute"
		} else if strings.HasPrefix(p, "~") {
			pType = "Home"
		}
		paths = append(paths, pathItem{Path: p, Type: pType})
	}
	return paths
}

// --- Extract subdomains ---
func extractSubdomains(content, base, rootDomain string) []string {
	matches := linkRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var subs []string
	for _, m := range matches {
		link := ""
		if m[1] != "" {
			link = m[1]
		} else if len(m) > 2 && m[2] != "" {
			link = m[2]
		} else if len(m) > 3 && m[3] != "" {
			link = m[3]
		}
		if link == "" {
			continue
		}
		u, err := url.Parse(link)
		if err != nil {
			continue
		}
		baseURL, _ := url.Parse(base)
		full := baseURL.ResolveReference(u)
		h := full.Hostname()
		if h == "" {
			continue
		}
		if h == rootDomain {
			continue
		}
		if strings.HasSuffix(h, "."+rootDomain) {
			if !seen[h] {
				seen[h] = true
				subs = append(subs, h)
			}
		}
	}
	return subs
}

// --- Fetch content ---
const maxBodySize = 10 * 1024 * 1024 // 10MB

func fetchURL(target string) (string, int, string, error) {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		DisableCompression:  false,
		DisableKeepAlives:   false,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   time.Duration(*flagTimeout) * time.Second,
	}
	req, err := http.NewRequest("GET", target, nil)
	if err != nil {
		return "", 0, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.1")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	
	resp, err := client.Do(req)
	if err != nil {
		return "", 0, "", err
	}
	defer resp.Body.Close()
	
	contentType := resp.Header.Get("Content-Type")
	
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
	if err != nil {
		return "", resp.StatusCode, contentType, err
	}
	
	if len(body) >= maxBodySize && *flagVerbose {
		fmt.Fprintf(os.Stderr, "%s[!]%s Response truncated at %dMB for %s\n", 
			colorYellow, colorReset, maxBodySize/(1024*1024), target)
	}
	
	return string(body), resp.StatusCode, contentType, nil
}

// --- Compile patterns (from patterns.go) ---
type compiledPattern struct {
	Name string
	Re   *regexp.Regexp
}

func compilePatterns() []compiledPattern {
	var compiled []compiledPattern
	var failedCount int

	for name, pattern := range RegexPatterns {
		// Check if pattern already has flags
		finalPattern := pattern
		if !strings.HasPrefix(pattern, "(?") {
			finalPattern = "(?m)" + pattern
		}
		
		re, err := regexp.Compile(finalPattern)
		if err != nil {
			if *flagVerbose {
				fmt.Fprintf(os.Stderr, "%s[!]%s Failed to compile pattern '%s': %v\n", 
					colorRed, colorReset, name, err)
			}
			failedCount++
			continue
		}
		compiled = append(compiled, compiledPattern{Name: name, Re: re})
	}

	if failedCount > 0 && !*flagSilent {
		fmt.Fprintf(os.Stderr, "%s[!]%s Warning: %d/%d patterns failed to compile\n", 
			colorYellow, colorReset, failedCount, len(RegexPatterns))
	}

	return compiled
}

type matchResult struct {
	PatternName string
	Match       string
}

func scanText(text string, compiled []compiledPattern) []matchResult {
	results := []matchResult{}
	seen := make(map[string]bool)
	
	for _, cp := range compiled {
		matches := cp.Re.FindAllString(text, -1)
		for _, m := range matches {
			key := cp.Name + ":" + m
			if !seen[key] {
				seen[key] = true
				results = append(results, matchResult{PatternName: cp.Name, Match: m})
			}
		}
	}
	return results
}

// --- Read URLs from file ---
func readLines(path string) ([]string, error) {
	path = expandPath(path)
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := strings.TrimSpace(scanner.Text())
		if s != "" && !strings.HasPrefix(s, "#") {
			lines = append(lines, s)
		}
	}
	return lines, scanner.Err()
}

// --- Show usage ---
func showUsage() {
	fmt.Fprintf(os.Stderr, `
%sJavaScript Secret & Endpoint Discovery Tool%s
Developed by github.com/vijay922

Usage:
  JSleuth [options]

Options:
  -u <url>          Scan a single URL
  -f <file>         Scan URLs from file (one per line)
  -secret           Enable secret pattern detection
  -links            Extract in-scope links
  -subs             Extract subdomains
  -path             Extract file system paths
  -custom <modes>   Comma-separated modes: links,path,secret,subs
  -o <file>         Save output to file
  -timeout <sec>    HTTP timeout in seconds (default: 10)
  -thread <num>     Number of concurrent threads (default: 5)
  -exclude <exts>   Exclude file extensions (e.g., png,jpg,svg)
  -s                Silent mode (no banner/summary)
  -v                Verbose mode (show detailed errors)
  -h                Show this help

Examples:
  JSleuth -u https://example.com/app.js -secret
  JSleuth -f urls.txt -secret -links -thread 10
  cat urls.txt | JSleuth -secret -o results.txt
  JSleuth -u https://example.com -custom secret,links -exclude png,jpg

`, colorGoldenBrown, colorReset)
}

// --- Main ---
func main() {
	flag.Usage = showUsage
	flag.Parse()

	if *flagHelp {
		showUsage()
		return
	}

	// Validate custom mode
	if *flagCustom != "" && (*flagLinks || *flagSubs || *flagPath || *flagSecret) {
		fmt.Fprintf(os.Stderr, "%s[!]%s Error: -custom cannot be used with -links, -subs, -path, or -secret\n", 
			colorRed, colorReset)
		os.Exit(1)
	}

	customModes := make(map[string]bool)
	if *flagCustom != "" {
		modes := strings.Split(strings.ToLower(*flagCustom), ",")
		for _, mode := range modes {
			mode = strings.TrimSpace(mode)
			if mode == "links" || mode == "subs" || mode == "path" || mode == "secret" {
				customModes[mode] = true
			} else {
				fmt.Fprintf(os.Stderr, "%s[!]%s Invalid custom mode: %s\n", colorRed, colorReset, mode)
				os.Exit(1)
			}
		}
	}

	// Validate at least one mode is selected
	if !*flagLinks && !*flagSubs && !*flagPath && !*flagSecret && *flagCustom == "" {
		fmt.Fprintf(os.Stderr, "%s[!]%s Error: At least one mode must be specified\n", colorRed, colorReset)
		fmt.Fprintf(os.Stderr, "Use -secret, -links, -subs, -path, or -custom\n")
		os.Exit(1)
	}

	var excludedExts []string
	if *flagExclude != "" {
		for _, e := range strings.Split(*flagExclude, ",") {
			e = strings.ToLower(strings.TrimSpace(e))
			if e != "" {
				excludedExts = append(excludedExts, e)
			}
		}
	}

	var f *os.File
	saveToFile := false
	if *flagOutfile != "" {
		p := expandPath(*flagOutfile)
		file, err := os.Create(p)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!]%s Cannot create file %s: %v\n", 
				colorRed, colorReset, p, err)
			os.Exit(1)
		}
		f = file
		defer f.Close()
		saveToFile = true
	}

	if !*flagSilent {
		fmt.Printf("%s", colorGoldenBrown)
		fmt.Println("╔══════════════════════════════════════════════════════════════╗")
		fmt.Println("║   JSleuth - JavaScript Secret & Endpoint Discovery Tool      ║")
		fmt.Println("║   Developed by github.com/vijay922                           ║")
		fmt.Println("╚══════════════════════════════════════════════════════════════╝")
		fmt.Printf("%s\n", colorReset)
	}

	var targets []string
	if *flagURL != "" {
		targets = append(targets, *flagURL)
	} else if *flagFile != "" {
		lines, err := readLines(*flagFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!]%s File read error: %v\n", colorRed, colorReset, err)
			os.Exit(1)
		}
		targets = append(targets, lines...)
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				t := strings.TrimSpace(sc.Text())
				if t != "" && !strings.HasPrefix(t, "#") {
					targets = append(targets, t)
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "%s[!]%s No input provided. Use -u, -f, or pipe input\n", 
				colorRed, colorReset)
			os.Exit(1)
		}
	}

	if len(targets) == 0 {
		fmt.Fprintf(os.Stderr, "%s[!]%s No valid targets found\n", colorRed, colorReset)
		os.Exit(1)
	}

	compiled := []compiledPattern{}
	if *flagSecret || customModes["secret"] {
		compiled = compilePatterns()
		if !*flagSilent {
			fmt.Printf("%s[+]%s Loaded %d/%d secret detection patterns\n", 
				colorGreen, colorReset, len(compiled), len(RegexPatterns))
		}
	}

	if !*flagSilent {
		fmt.Printf("%s[+]%s Starting scan on %d target(s) with %d thread(s)\n", 
			colorGreen, colorReset, len(targets), *flagThread)
		fmt.Println()
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, *flagThread)
	resultsCh := make(chan string, len(targets)*2)
	start := time.Now()

	uniqueFound := make(map[string]bool)
	var mu sync.Mutex

	// Progress indicator
	stopProgress := make(chan bool)
	if !*flagSilent && len(targets) > 5 {
		go func() {
			ticker := time.NewTicker(3 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					processed := atomic.LoadInt64(&stats.Processed)
					errors := atomic.LoadInt64(&stats.Errors)
					fmt.Fprintf(os.Stderr, "\r%s[Progress]%s %d/%d URLs processed | %d errors", 
						colorBlue, colorReset, processed, len(targets), errors)
				case <-stopProgress:
					fmt.Fprintf(os.Stderr, "\r%s", strings.Repeat(" ", 80))
					fmt.Fprintf(os.Stderr, "\r")
					return
				}
			}
		}()
	}

	for i, t := range targets {
		index := i + 1
		target := t
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			body, statusCode, contentType, err := fetchURL(target)
			atomic.AddInt64(&stats.Processed, 1)
			
			if err != nil {
				if *flagVerbose {
					fmt.Fprintf(os.Stderr, "%s[!]%s Error fetching %s: %v\n", 
						colorRed, colorReset, target, err)
				}
				atomic.AddInt64(&stats.Errors, 1)
				return
			}

			if statusCode != 200 && *flagVerbose {
				fmt.Fprintf(os.Stderr, "%s[!]%s Non-200 status for %s: %d\n", 
					colorYellow, colorReset, target, statusCode)
			}

			// Optional: Warn if not JavaScript content for secret scanning
			if (*flagSecret || customModes["secret"]) && !strings.Contains(strings.ToLower(contentType), "javascript") && 
			   !strings.Contains(strings.ToLower(contentType), "ecmascript") &&
			   !strings.HasSuffix(strings.ToLower(target), ".js") && *flagVerbose {
				fmt.Fprintf(os.Stderr, "%s[!]%s Warning: %s may not be JavaScript (Content-Type: %s)\n", 
					colorYellow, colorReset, target, contentType)
			}

			root := getRootDomain(target)
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("%s[URL %d/%d]%s %s\n", 
				colorBlue, index, len(targets), colorReset, target))

			foundAny := false

			if *flagLinks || customModes["links"] {
				for i, l := range extractLinks(body, target, root, excludedExts) {
					key := "link:" + l.URL
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						mu.Unlock()
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, l.URL, colorReset)
						sb.WriteString(fmt.Sprintf("  %s[Link-%s #%d]%s %s\n", 
							colorGreen, l.Type, i+1, colorReset, colored))
						atomic.AddInt64(&stats.Links, 1)
						foundAny = true
					} else {
						mu.Unlock()
					}
				}
			}

			if *flagPath || customModes["path"] {
				for i, p := range extractPaths(body, excludedExts) {
					key := "path:" + p.Path
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						mu.Unlock()
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, p.Path, colorReset)
						sb.WriteString(fmt.Sprintf("  %s[Path-%s #%d]%s %s\n", 
							colorGreen, p.Type, i+1, colorReset, colored))
						atomic.AddInt64(&stats.Paths, 1)
						foundAny = true
					} else {
						mu.Unlock()
					}
				}
			}

			if *flagSubs || customModes["subs"] {
				for i, s := range extractSubdomains(body, target, root) {
					mu.Lock()
					if !uniqueFound[s] {
						uniqueFound[s] = true
						mu.Unlock()
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, s, colorReset)
						sb.WriteString(fmt.Sprintf("  %s[Subdomain #%d]%s %s\n", 
							colorGreen, i+1, colorReset, colored))
						atomic.AddInt64(&stats.Subdomains, 1)
						foundAny = true
					} else {
						mu.Unlock()
					}
				}
			}

			if *flagSecret || customModes["secret"] {
				for _, m := range scanText(body, compiled) {
					key := m.PatternName + ":" + m.Match
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						mu.Unlock()
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, m.Match, colorReset)
						sb.WriteString(fmt.Sprintf("  %s[%s]%s %s\n", 
							colorRed, strings.ToUpper(m.PatternName), colorReset, colored))
						atomic.AddInt64(&stats.Secrets, 1)
						foundAny = true
					} else {
						mu.Unlock()
					}
				}
			}

			if foundAny {
				sb.WriteString("\n")
				resultsCh <- sb.String()
			}
		}()
	}

	go func() {
		wg.Wait()
		close(resultsCh)
		if !*flagSilent && len(targets) > 5 {
			stopProgress <- true
		}
	}()

	for res := range resultsCh {
		fmt.Print(res)
		if saveToFile && f != nil {
			f.WriteString(stripANSI(res))
		}
	}

	if !*flagSilent {
		duration := time.Since(start)
		minutes := int(duration.Minutes())
		seconds := int(duration.Seconds()) - minutes*60

		fmt.Println(strings.Repeat("═", 60))
		fmt.Printf("%s[Summary]%s\n", colorGreen, colorReset)
		fmt.Println(strings.Repeat("─", 60))
		fmt.Printf("  Total URLs Processed:  %d\n", atomic.LoadInt64(&stats.Processed))
		fmt.Printf("  Links Found:           %s%d%s\n", colorGoldenBrown, atomic.LoadInt64(&stats.Links), colorReset)
		fmt.Printf("  Paths Found:           %s%d%s\n", colorGoldenBrown, atomic.LoadInt64(&stats.Paths), colorReset)
		fmt.Printf("  Subdomains Found:      %s%d%s\n", colorGoldenBrown, atomic.LoadInt64(&stats.Subdomains), colorReset)
		fmt.Printf("  Secrets Found:         %s%d%s\n", colorRed, atomic.LoadInt64(&stats.Secrets), colorReset)
		fmt.Printf("  Errors:                %s%d%s\n", colorRed, atomic.LoadInt64(&stats.Errors), colorReset)
		fmt.Printf("  Time Taken:            %dm %ds\n", minutes, seconds)
		
		if saveToFile {
			fmt.Printf("  Output Saved:          %s%s%s\n", colorGreen, *flagOutfile, colorReset)
		}
		fmt.Println(strings.Repeat("═", 60))
	}
}
