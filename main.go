package main

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
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
	colorCyan        = "\033[36m"
	colorMagenta     = "\033[35m"
)

// --- Flags ---
var (
	flagURL       = flag.String("u", "", "Scan a single URL (http[s]://...)")
	flagFile      = flag.String("f", "", "Scan URLs from file (one per line)")
	flagSecret    = flag.Bool("secret", false, "Detect secret patterns using regex")
	flagLinks     = flag.Bool("links", false, "Extract in-scope links (relative + absolute)")
	flagSubs      = flag.Bool("subs", false, "Extract only subdomains for the target's root domain")
	flagPath      = flag.Bool("path", false, "Extract file system paths (absolute, relative, home-relative)")
	flagAPI       = flag.Bool("api", false, "Extract API endpoints and parameters")
	flagJS        = flag.Bool("js", false, "Extract JavaScript variables, functions, and sensitive comments")
	flagCustom    = flag.String("custom", "", "Custom mode: comma-separated list (links,path,secret,subs,api,js)")
	flagOutfile   = flag.String("o", "", "Save output to plain text file (optional)")
	flagJSON      = flag.String("json", "", "Save output in JSON format")
	flagTimeout   = flag.Int("timeout", 10, "HTTP request timeout in seconds")
	flagThread    = flag.Int("thread", 5, "Number of concurrent threads")
	flagExclude   = flag.String("exclude", "", "Comma-separated list of extensions to exclude (e.g. png,jpg,svg)")
	flagSilent    = flag.Bool("s", false, "Silent mode (hide banner and summary)")
	flagVerbose   = flag.Bool("v", false, "Verbose mode (show detailed errors)")
	flagDeep      = flag.Bool("deep", false, "Deep scan: decode base64, parse JSON, extract from comments")
	flagHeaders   = flag.Bool("headers", false, "Extract sensitive headers and cookies")
	flagRetry     = flag.Int("retry", 2, "Number of retries on failure")
	flagFollowRedir = flag.Bool("follow", true, "Follow redirects")
	flagMinified  = flag.Bool("minified", false, "Include results from minified JS (more false positives)")
	flagHelp      = flag.Bool("h", false, "Show help")
)

// --- Statistics ---
type Stats struct {
	Links      int64
	Paths      int64
	Subdomains int64
	Secrets    int64
	APIs       int64
	JSVars     int64
	Comments   int64
	Errors     int64
	Processed  int64
	Headers    int64
}

var stats Stats

// --- Result structures for JSON output ---
type ScanResult struct {
	URL        string          `json:"url"`
	StatusCode int             `json:"status_code"`
	Links      []linkItem      `json:"links,omitempty"`
	Paths      []pathItem      `json:"paths,omitempty"`
	Subdomains []string        `json:"subdomains,omitempty"`
	Secrets    []matchResult   `json:"secrets,omitempty"`
	APIs       []apiItem       `json:"apis,omitempty"`
	JSFindings []jsItem        `json:"js_findings,omitempty"`
	Headers    []headerItem    `json:"headers,omitempty"`
	Timestamp  string          `json:"timestamp"`
}

var allResults []ScanResult
var resultsMutex sync.Mutex

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

// --- Enhanced Link extraction ---
var linkRegex = regexp.MustCompile(`(?i)(?:href|src|url|action|data-url|data-src|srcset|data-href|formaction)\s*=\s*["']([^"'>\s]+)["']|fetch\(["']([^"']+)["']\)|import\s*\(["']([^"']+)["']\)|XMLHttpRequest.*?open\(["'](?:GET|POST)["'],\s*["']([^"']+)["']|axios\.(?:get|post|put|delete)\(["']([^"']+)["']|\$\.(?:ajax|get|post)\(["']([^"']+)["']|window\.location(?:\.href)?\s*=\s*["']([^"']+)["']`)

type linkItem struct {
	URL  string `json:"url"`
	Type string `json:"type"`
}

func extractLinks(content, base, rootDomain string, excludedExts []string) []linkItem {
	matches := linkRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var links []linkItem

	for _, m := range matches {
		link := ""
		for i := 1; i < len(m); i++ {
			if m[i] != "" {
				link = m[i]
				break
			}
		}
		if link == "" {
			continue
		}

		// Skip data URIs, javascript:, mailto:, etc.
		if strings.HasPrefix(link, "data:") || 
		   strings.HasPrefix(link, "javascript:") || 
		   strings.HasPrefix(link, "mailto:") ||
		   strings.HasPrefix(link, "tel:") ||
		   strings.HasPrefix(link, "#") {
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

// --- Enhanced file system paths extraction ---
var pathRegex = regexp.MustCompile(`(?m)(?:["'\s]|^|:)(~?/[A-Za-z0-9._\-/]+|(?:\.\.?/)+[A-Za-z0-9._\-/]+|[A-Z]:\\[\w\\\-./]+)(?:["'\s]|$|,)`)

type pathItem struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

func extractPaths(content string, excludedExts []string) []pathItem {
	matches := pathRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var paths []pathItem

	for _, m := range matches {
		p := strings.TrimSpace(m[1])
		if p == "" || seen[p] || len(p) < 2 {
			continue
		}
		// Filter out common false positives
		if strings.HasPrefix(p, "//") || strings.Contains(p, "http") {
			continue
		}
		if shouldExclude(p, excludedExts) {
			continue
		}
		seen[p] = true

		pType := "Relative"
		if strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "//") {
			pType = "Absolute"
		} else if strings.HasPrefix(p, "~") {
			pType = "Home"
		} else if len(p) > 2 && p[1] == ':' {
			pType = "Windows"
		}
		paths = append(paths, pathItem{Path: p, Type: pType})
	}
	return paths
}

// --- API endpoint extraction ---
type apiItem struct {
	Endpoint   string   `json:"endpoint"`
	Method     string   `json:"method,omitempty"`
	Parameters []string `json:"parameters,omitempty"`
}

var apiRegex = regexp.MustCompile(`(?i)(?:["'\s]|^)((?:https?://[^/\s]+)?/(?:api|rest|graphql|v\d+)[/a-z0-9_\-{}]+)(?:["'\s]|$)`)
var methodRegex = regexp.MustCompile(`(?i)(?:\.(?:get|post|put|delete|patch|head|options)|(?:method|type)[\s]*[=:]\s*["'])(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)["']?\s*[,\s]+\s*(?:url[\s]*[=:]\s*)?["']([/a-z0-9_\-{}:]+)["']`)
var urlPatternRegex = regexp.MustCompile(`(?i)(?:url|endpoint|path|route)[\s]*[=:]\s*["']([/a-z0-9_\-{}:]+)["']`)
var paramRegex = regexp.MustCompile(`(?i)(?:\?|&)([a-zA-Z_][a-zA-Z0-9_]{2,})=|(?:params|query|data)[\s]*[=:]\s*\{[^}]*["']([a-zA-Z_][a-zA-Z0-9_]{2,})["']`)

func extractAPIs(content string) []apiItem {
	seen := make(map[string]bool)
	var apis []apiItem
	
	// Filter function to check if endpoint is valid
	isValidEndpoint := func(endpoint string) bool {
		// Must start with /
		if !strings.HasPrefix(endpoint, "/") && !strings.HasPrefix(endpoint, "http") {
			return false
		}
		// Must have reasonable length
		if len(endpoint) < 4 || len(endpoint) > 200 {
			return false
		}
		// Filter out common false positives
		falsePositives := []string{
			"/vendor/", "/node_modules/", "/dist/", "/build/",
			"/static/", "/assets/", "/images/", "/css/", "/js/",
		}
		lower := strings.ToLower(endpoint)
		for _, fp := range falsePositives {
			if strings.Contains(lower, fp) {
				return false
			}
		}
		return true
	}

	// Extract API paths with context
	apiMatches := apiRegex.FindAllStringSubmatch(content, -1)
	for _, m := range apiMatches {
		if len(m) > 1 {
			match := m[1]
			if isValidEndpoint(match) && !seen[match] {
				seen[match] = true
				apis = append(apis, apiItem{Endpoint: match})
			}
		}
	}

	// Extract method + endpoint combinations
	methodMatches := methodRegex.FindAllStringSubmatch(content, -1)
	for _, m := range methodMatches {
		if len(m) > 1 {
			endpoint := m[1]
			if isValidEndpoint(endpoint) && !seen[endpoint] {
				seen[endpoint] = true
				
				// Try to find method in the match
				method := ""
				methodNames := []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}
				for _, mName := range methodNames {
					if strings.Contains(strings.ToUpper(m[0]), mName) {
						method = mName
						break
					}
				}
				
				// Extract parameters specific to this endpoint
				params := extractEndpointParams(content, endpoint)
				
				apis = append(apis, apiItem{
					Endpoint:   endpoint,
					Method:     method,
					Parameters: params,
				})
			}
		}
	}

	// Extract URL patterns
	urlMatches := urlPatternRegex.FindAllStringSubmatch(content, -1)
	for _, m := range urlMatches {
		if len(m) > 1 {
			endpoint := m[1]
			if isValidEndpoint(endpoint) && !seen[endpoint] {
				seen[endpoint] = true
				apis = append(apis, apiItem{Endpoint: endpoint})
			}
		}
	}

	return apis
}

func extractEndpointParams(content, endpoint string) []string {
	seen := make(map[string]bool)
	var params []string
	
	// Look for parameters in a reasonable window around the endpoint
	endpointIndex := strings.Index(content, endpoint)
	if endpointIndex == -1 {
		return params
	}
	
	// Search within 500 characters before and after
	start := max(0, endpointIndex-500)
	end := min(len(content), endpointIndex+len(endpoint)+500)
	window := content[start:end]
	
	paramMatches := paramRegex.FindAllStringSubmatch(window, -1)
	for _, pm := range paramMatches {
		for i := 1; i < len(pm); i++ {
			if pm[i] != "" && len(pm[i]) > 2 && len(pm[i]) < 30 && !seen[pm[i]] {
				// Filter out common minified variable names
				if !isMinifiedVar(pm[i]) {
					seen[pm[i]] = true
					params = append(params, pm[i])
					if len(params) >= 10 {
						return params
					}
				}
			}
		}
	}
	
	return params
}

func isMinifiedVar(name string) bool {
	// Single letter or very short names
	if len(name) <= 2 {
		return true
	}
	// Common minified patterns
	minifiedPatterns := []string{"exports", "module", "require", "define"}
	for _, pattern := range minifiedPatterns {
		if name == pattern {
			return true
		}
	}
	return false
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- JavaScript analysis ---
type jsItem struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

var (
	varRegex      = regexp.MustCompile(`(?i)(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]{2,})\s*=\s*["']([^"']{5,})["']`)
	functionRegex = regexp.MustCompile(`(?i)function\s+([a-zA-Z_$][a-zA-Z0-9_$]{3,})\s*\(`)
	commentRegex  = regexp.MustCompile(`(?://[^\n]*(?:password|secret|key|token|api|credential|auth|todo|fixme|hack|bug)[^\n]*|/\*[^*]*(?:password|secret|key|token|api|credential|auth|todo|fixme|hack|bug)[^*]*\*/)`)
	configRegex   = regexp.MustCompile(`(?i)(?:config|settings|options)\s*[=:]\s*\{([^}]+)\}`)
)

func extractJSFindings(content string) []jsItem {
	var findings []jsItem
	seen := make(map[string]bool)

	// Extract sensitive variables (with better filtering)
	varMatches := varRegex.FindAllStringSubmatch(content, -1)
	for _, m := range varMatches {
		if len(m) > 2 {
			varName := m[1]
			varValue := m[2]
			
			// Skip if looks like minified code
			if len(varName) <= 2 || isMinifiedVar(varName) {
				continue
			}
			
			varNameLower := strings.ToLower(varName)
			sensitiveKeywords := []string{"key", "token", "secret", "password", "api", "auth", "credential"}
			isSensitive := false
			
			for _, keyword := range sensitiveKeywords {
				if strings.Contains(varNameLower, keyword) {
					isSensitive = true
					break
				}
			}
			
			if isSensitive {
				key := "var:" + varName
				if !seen[key] {
					seen[key] = true
					findings = append(findings, jsItem{
						Type:  "Variable",
						Name:  varName,
						Value: varValue[:min(len(varValue), 80)], // Truncate long values
					})
				}
			}
		}
	}

	// Extract function names (filter minified)
	funcMatches := functionRegex.FindAllStringSubmatch(content, -1)
	funcCount := 0
	for _, m := range funcMatches {
		if len(m) > 1 && funcCount < 15 { // Limit to 15 functions
			funcName := m[1]
			
			// Skip single/double letter functions and common minified names
			if len(funcName) <= 2 || isMinifiedVar(funcName) {
				continue
			}
			
			key := "func:" + funcName
			if !seen[key] {
				seen[key] = true
				findings = append(findings, jsItem{
					Type: "Function",
					Name: funcName,
				})
				funcCount++
			}
		}
	}

	// Extract sensitive comments
	commentMatches := commentRegex.FindAllString(content, -1)
	commentCount := 0
	for _, match := range commentMatches {
		if commentCount >= 10 { // Limit to 10 comments
			break
		}
		
		cleanMatch := strings.TrimSpace(match)
		if len(cleanMatch) < 15 || len(cleanMatch) > 200 {
			continue
		}
		
		key := "comment:" + cleanMatch
		if !seen[key] {
			seen[key] = true
			findings = append(findings, jsItem{
				Type:  "Comment",
				Value: cleanMatch,
			})
			atomic.AddInt64(&stats.Comments, 1)
			commentCount++
		}
	}

	return findings
}

// --- Header extraction ---
type headerItem struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func extractSensitiveHeaders(headers http.Header) []headerItem {
	var sensitive []headerItem
	sensitiveHeaders := []string{
		"authorization", "x-api-key", "x-auth-token", "cookie",
		"set-cookie", "x-csrf-token", "x-xsrf-token", "api-key",
		"x-access-token", "x-refresh-token", "jwt",
	}

	for _, name := range sensitiveHeaders {
		if val := headers.Get(name); val != "" {
			sensitive = append(sensitive, headerItem{
				Name:  name,
				Value: val[:min(len(val), 100)], // Truncate long values
			})
		}
	}

	return sensitive
}

// --- Deep scan features ---
func deepScan(content string) string {
	if !*flagDeep {
		return content
	}

	// Decode base64 strings
	base64Regex := regexp.MustCompile(`(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`)
	matches := base64Regex.FindAllString(content, -1)
	
	for _, match := range matches {
		if len(match) > 20 && len(match) < 1000 { // Reasonable base64 length
			decoded, err := base64.StdEncoding.DecodeString(match)
			if err == nil && isPrintable(string(decoded)) {
				content += "\n[DECODED_BASE64] " + string(decoded)
			}
		}
	}

	// Extract from JSON strings
	var jsonData interface{}
	if err := json.Unmarshal([]byte(content), &jsonData); err == nil {
		if jsonStr, err := json.MarshalIndent(jsonData, "", "  "); err == nil {
			content += "\n[PARSED_JSON] " + string(jsonStr)
		}
	}

	return content
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}

// --- Extract subdomains ---
func extractSubdomains(content, base, rootDomain string) []string {
	matches := linkRegex.FindAllStringSubmatch(content, -1)
	seen := make(map[string]bool)
	var subs []string
	for _, m := range matches {
		link := ""
		for i := 1; i < len(m); i++ {
			if m[i] != "" {
				link = m[i]
				break
			}
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
		if h == "" || h == rootDomain {
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

// --- Fetch content with retry ---
const maxBodySize = 10 * 1024 * 1024 // 10MB

func fetchURL(target string) (string, int, string, http.Header, error) {
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
	
	if !*flagFollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	var lastErr error
	for attempt := 0; attempt <= *flagRetry; attempt++ {
		if attempt > 0 && *flagVerbose {
			fmt.Fprintf(os.Stderr, "%s[Retry %d/%d]%s %s\n", 
				colorYellow, attempt, *flagRetry, colorReset, target)
			time.Sleep(time.Duration(attempt) * time.Second)
		}

		req, err := http.NewRequest("GET", target, nil)
		if err != nil {
			lastErr = err
			continue
		}
		
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		
		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()
		
		contentType := resp.Header.Get("Content-Type")
		
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodySize))
		if err != nil {
			lastErr = err
			continue
		}
		
		return string(body), resp.StatusCode, contentType, resp.Header, nil
	}
	
	return "", 0, "", nil, lastErr
}

// --- Compile patterns ---
type compiledPattern struct {
	Name string
	Re   *regexp.Regexp
}

func compilePatterns() []compiledPattern {
	var compiled []compiledPattern
	var failedCount int

	for name, pattern := range RegexPatterns {
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
	PatternName string `json:"pattern"`
	Match       string `json:"match"`
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
%sJavaScript Secret & Endpoint Discovery Tool (Enhanced)%s
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
  -api              Extract API endpoints and parameters
  -js               Extract JS variables, functions, and comments
  -custom <modes>   Comma-separated: links,path,secret,subs,api,js
  -o <file>         Save output to text file
  -json <file>      Save output in JSON format
  -timeout <sec>    HTTP timeout (default: 10)
  -thread <num>     Concurrent threads (default: 5)
  -retry <num>      Retry attempts on failure (default: 2)
  -exclude <exts>   Exclude extensions (e.g., png,jpg,svg)
  -deep             Deep scan: decode base64, parse JSON
  -headers          Extract sensitive headers
  -follow           Follow redirects (default: true)
  -s                Silent mode
  -v                Verbose mode
  -h                Show help

Examples:
  JSleuth -u https://example.com/app.js -secret -deep
  JSleuth -f urls.txt -api -js -json results.json
  JSleuth -u https://example.com -custom secret,api,js -thread 10
  cat urls.txt | JSleuth -secret -links -headers -o results.txt

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
	if *flagCustom != "" && (*flagLinks || *flagSubs || *flagPath || *flagSecret || *flagAPI || *flagJS) {
		fmt.Fprintf(os.Stderr, "%s[!]%s Error: -custom cannot be used with other mode flags\n", 
			colorRed, colorReset)
		os.Exit(1)
	}

	customModes := make(map[string]bool)
	if *flagCustom != "" {
		modes := strings.Split(strings.ToLower(*flagCustom), ",")
		for _, mode := range modes {
			mode = strings.TrimSpace(mode)
			validModes := []string{"links", "subs", "path", "secret", "api", "js"}
			valid := false
			for _, vm := range validModes {
				if mode == vm {
					valid = true
					customModes[mode] = true
					break
				}
			}
			if !valid {
				fmt.Fprintf(os.Stderr, "%s[!]%s Invalid custom mode: %s\n", colorRed, colorReset, mode)
				os.Exit(1)
			}
		}
	}

	// Validate at least one mode
	if !*flagLinks && !*flagSubs && !*flagPath && !*flagSecret && !*flagAPI && !*flagJS && *flagCustom == "" {
		fmt.Fprintf(os.Stderr, "%s[!]%s Error: At least one mode must be specified\n", colorRed, colorReset)
		fmt.Fprintf(os.Stderr, "Use -secret, -links, -subs, -path, -api, -js, or -custom\n")
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
		fmt.Println("║   JSleuth - Enhanced JavaScript Discovery Tool               ║")
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
		enabledModes := []string{}
		if *flagSecret || customModes["secret"] {
			enabledModes = append(enabledModes, "secret")
		}
		if *flagLinks || customModes["links"] {
			enabledModes = append(enabledModes, "links")
		}
		if *flagPath || customModes["path"] {
			enabledModes = append(enabledModes, "path")
		}
		if *flagSubs || customModes["subs"] {
			enabledModes = append(enabledModes, "subs")
		}
		if *flagAPI || customModes["api"] {
			enabledModes = append(enabledModes, "api")
		}
		if *flagJS || customModes["js"] {
			enabledModes = append(enabledModes, "js")
		}
		if *flagHeaders {
			enabledModes = append(enabledModes, "headers")
		}
		if *flagDeep {
			enabledModes = append(enabledModes, "deep-scan")
		}
		
		fmt.Printf("%s[+]%s Modes enabled: %s\n", 
			colorGreen, colorReset, strings.Join(enabledModes, ", "))
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

			body, statusCode, _, headers, err := fetchURL(target)
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

			// Apply deep scan if enabled
			if *flagDeep {
				body = deepScan(body)
			}

			root := getRootDomain(target)
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("%s[URL %d/%d]%s %s %s(Status: %d)%s\n", 
				colorBlue, index, len(targets), colorReset, target, colorCyan, statusCode, colorReset))

			foundAny := false
			
			// Prepare result for JSON output
			result := ScanResult{
				URL:        target,
				StatusCode: statusCode,
				Timestamp:  time.Now().Format(time.RFC3339),
			}

			// Extract headers
			if *flagHeaders {
				headerItems := extractSensitiveHeaders(headers)
				result.Headers = headerItems
				for _, h := range headerItems {
					mu.Lock()
					key := "header:" + h.Name + ":" + target
					if !uniqueFound[key] {
						uniqueFound[key] = true
						mu.Unlock()
						colored := fmt.Sprintf("%s%s: %s%s", colorMagenta, h.Name, h.Value, colorReset)
						sb.WriteString(fmt.Sprintf("  %s[Header]%s %s\n", 
							colorMagenta, colorReset, colored))
						atomic.AddInt64(&stats.Headers, 1)
						foundAny = true
					} else {
						mu.Unlock()
					}
				}
			}

			// Extract links
			if *flagLinks || customModes["links"] {
				links := extractLinks(body, target, root, excludedExts)
				result.Links = links
				for i, l := range links {
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

			// Extract paths
			if *flagPath || customModes["path"] {
				paths := extractPaths(body, excludedExts)
				result.Paths = paths
				for i, p := range paths {
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

			// Extract subdomains
			if *flagSubs || customModes["subs"] {
				subs := extractSubdomains(body, target, root)
				result.Subdomains = subs
				for i, s := range subs {
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

			// Extract API endpoints
			if *flagAPI || customModes["api"] {
				apis := extractAPIs(body)
				result.APIs = apis
				for i, api := range apis {
					key := "api:" + api.Endpoint
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						mu.Unlock()
						colored := fmt.Sprintf("%s%s%s", colorGoldenBrown, api.Endpoint, colorReset)
						methodStr := ""
						if api.Method != "" {
							methodStr = fmt.Sprintf(" %s[%s]%s", colorCyan, api.Method, colorReset)
						}
						paramsStr := ""
						if len(api.Parameters) > 0 {
							paramsStr = fmt.Sprintf(" %s(params: %s)%s", 
								colorYellow, strings.Join(api.Parameters[:min(len(api.Parameters), 5)], ", "), colorReset)
						}
						sb.WriteString(fmt.Sprintf("  %s[API #%d]%s %s%s%s\n", 
							colorCyan, i+1, colorReset, colored, methodStr, paramsStr))
						atomic.AddInt64(&stats.APIs, 1)
						foundAny = true
					} else {
						mu.Unlock()
					}
				}
			}

			// Extract JS findings
			if *flagJS || customModes["js"] {
				jsFindings := extractJSFindings(body)
				result.JSFindings = jsFindings
				for i, js := range jsFindings {
					key := "js:" + js.Type + ":" + js.Name
					mu.Lock()
					if !uniqueFound[key] {
						uniqueFound[key] = true
						mu.Unlock()
						var colored string
						if js.Value != "" {
							colored = fmt.Sprintf("%s%s%s = %s%s%s", 
								colorMagenta, js.Name, colorReset, 
								colorGoldenBrown, js.Value, colorReset)
						} else if js.Name != "" {
							colored = fmt.Sprintf("%s%s%s", colorMagenta, js.Name, colorReset)
						} else {
							colored = fmt.Sprintf("%s%s%s", colorYellow, js.Value, colorReset)
						}
						sb.WriteString(fmt.Sprintf("  %s[JS-%s #%d]%s %s\n", 
							colorMagenta, js.Type, i+1, colorReset, colored))
						atomic.AddInt64(&stats.JSVars, 1)
						foundAny = true
					} else {
						mu.Unlock()
					}
				}
			}

			// Scan for secrets
			if *flagSecret || customModes["secret"] {
				secrets := scanText(body, compiled)
				result.Secrets = secrets
				for _, m := range secrets {
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
				
				// Store result for JSON output
				if *flagJSON != "" {
					resultsMutex.Lock()
					allResults = append(allResults, result)
					resultsMutex.Unlock()
				}
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

	// Save JSON output
	if *flagJSON != "" {
		jsonPath := expandPath(*flagJSON)
		jsonFile, err := os.Create(jsonPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s[!]%s Cannot create JSON file: %v\n", 
				colorRed, colorReset, err)
		} else {
			defer jsonFile.Close()
			encoder := json.NewEncoder(jsonFile)
			encoder.SetIndent("", "  ")
			if err := encoder.Encode(map[string]interface{}{
				"scan_date": time.Now().Format(time.RFC3339),
				"total_urls": len(targets),
				"results": allResults,
				"statistics": map[string]int64{
					"links":      atomic.LoadInt64(&stats.Links),
					"paths":      atomic.LoadInt64(&stats.Paths),
					"subdomains": atomic.LoadInt64(&stats.Subdomains),
					"secrets":    atomic.LoadInt64(&stats.Secrets),
					"apis":       atomic.LoadInt64(&stats.APIs),
					"js_vars":    atomic.LoadInt64(&stats.JSVars),
					"headers":    atomic.LoadInt64(&stats.Headers),
					"errors":     atomic.LoadInt64(&stats.Errors),
				},
			}); err != nil {
				fmt.Fprintf(os.Stderr, "%s[!]%s Error writing JSON: %v\n", 
					colorRed, colorReset, err)
			} else if !*flagSilent {
				fmt.Printf("%s[+]%s JSON output saved to: %s\n", 
					colorGreen, colorReset, jsonPath)
			}
		}
	}

	if !*flagSilent {
		duration := time.Since(start)
		minutes := int(duration.Minutes())
		seconds := int(duration.Seconds()) - minutes*60

		fmt.Println(strings.Repeat("═", 70))
		fmt.Printf("%s[Summary]%s\n", colorGreen, colorReset)
		fmt.Println(strings.Repeat("─", 70))
		fmt.Printf("  Total URLs Processed:  %d\n", atomic.LoadInt64(&stats.Processed))
		fmt.Printf("  Links Found:           %s%d%s\n", colorGoldenBrown, atomic.LoadInt64(&stats.Links), colorReset)
		fmt.Printf("  Paths Found:           %s%d%s\n", colorGoldenBrown, atomic.LoadInt64(&stats.Paths), colorReset)
		fmt.Printf("  Subdomains Found:      %s%d%s\n", colorGoldenBrown, atomic.LoadInt64(&stats.Subdomains), colorReset)
		fmt.Printf("  APIs Found:            %s%d%s\n", colorCyan, atomic.LoadInt64(&stats.APIs), colorReset)
		fmt.Printf("  JS Variables Found:    %s%d%s\n", colorMagenta, atomic.LoadInt64(&stats.JSVars), colorReset)
		fmt.Printf("  Secrets Found:         %s%d%s\n", colorRed, atomic.LoadInt64(&stats.Secrets), colorReset)
		if *flagHeaders {
			fmt.Printf("  Sensitive Headers:     %s%d%s\n", colorMagenta, atomic.LoadInt64(&stats.Headers), colorReset)
		}
		fmt.Printf("  Errors:                %s%d%s\n", colorRed, atomic.LoadInt64(&stats.Errors), colorReset)
		fmt.Printf("  Time Taken:            %dm %ds\n", minutes, seconds)
		
		if saveToFile {
			fmt.Printf("  Output Saved:          %s%s%s\n", colorGreen, *flagOutfile, colorReset)
		}
		if *flagJSON != "" {
			fmt.Printf("  JSON Saved:            %s%s%s\n", colorGreen, *flagJSON, colorReset)
		}
		fmt.Println(strings.Repeat("═", 70))
	}
}
