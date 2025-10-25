# JSleuth
JSleuth is an open-source project designed to help security researchers, bug bounty hunters, and developers identify secrets and sensitive information embedded within JavaScript files, web responses, and URLs.

# JSleuth - JavaScript Secret & Endpoint Discovery Tool

<div align="center">

![Version](https://img.shields.io/badge/version-2.0.1-blue.svg)
![Go Version](https://img.shields.io/badge/Go-1.19+-00ADD8.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)

**A powerful Go-based tool for discovering secrets, API keys, tokens, and endpoints in JavaScript files**

[Features](#features) • [Installation](#installation) • [Usage](#usage) • [Examples](#examples) • [Contributing](#contributing)

</div>

---

## 📋 Table of Contents

- [About](#about)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Detection Patterns](#detection-patterns)
- [Examples](#examples)
- [Output](#output)
- [Performance](#performance)
- [Contributing](#contributing)
- [Disclaimer](#disclaimer)
- [License](#license)
- [Author](#author)

---

## 🎯 About

**JSleuth** is a high-performance security reconnaissance tool specifically designed for bug bounty hunters and security researchers. It analyzes JavaScript files to discover:

- 🔐 **180+ Secret Patterns**: API keys, OAuth tokens, access credentials
- 🔗 **In-Scope Links**: Relative and absolute URLs within the target domain
- 📁 **File System Paths**: Absolute, relative, and home directory paths
- 🌐 **Subdomains**: Hidden subdomains referenced in JavaScript
- 🎯 **Attack Surface**: Endpoints, webhooks, and internal URLs

JSleuth uses carefully crafted regex patterns based on real-world token formats from major cloud providers, payment gateways, and development platforms.

---

## ✨ Features

### 🔍 Multi-Mode Scanning
- **Secret Detection**: 180+ regex patterns for API keys, tokens, and credentials
- **Link Extraction**: Discover all in-scope URLs (relative & absolute)
- **Subdomain Enumeration**: Find hidden subdomains
- **Path Discovery**: Extract file system paths from JavaScript

### ⚡ Performance & Efficiency
- **Concurrent Processing**: Multi-threaded scanning with configurable workers
- **Smart Filtering**: Extension-based exclusion (png, jpg, svg, etc.)
- **Progress Tracking**: Real-time progress indicator for large scans
- **Memory Efficient**: 10MB body size limit with streaming

### 🎨 User Experience
- **Colored Output**: Beautiful golden-brown highlighting for findings
- **Detailed Statistics**: Comprehensive summary with breakdown by type
- **Verbose Mode**: Detailed error logging for debugging
- **Silent Mode**: Clean output for automation and pipelines

### 🔧 Input Flexibility
- Single URL scanning (`-u`)
- Batch file processing (`-f`)
- Pipeline support (stdin)
- Comment support in input files

---

## 📦 Installation

### Prerequisites
- Go 1.19 or higher

### Build from Source

```bash
# Clone the repository
git clone https://github.com/vijay922/JSleuth.git
cd JSleuth

# Build the binary
go build -o jsleuth main.go patterns.go

# Make executable (Linux/macOS)
chmod +x jsleuth

# Move to PATH (optional)
sudo mv jsleuth /usr/local/bin/
```

### Quick Install (One-liner)

```bash
go install github.com/vijay922/JSleuth@latest
```

---

## 🚀 Usage

### Basic Syntax

```bash
jsleuth [options]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-u <url>` | Scan a single URL | - |
| `-f <file>` | Scan URLs from file (one per line) | - |
| `-secret` | Enable secret pattern detection | false |
| `-links` | Extract in-scope links | false |
| `-subs` | Extract subdomains | false |
| `-path` | Extract file system paths | false |
| `-custom <modes>` | Comma-separated modes: `links,path,secret,subs` | - |
| `-o <file>` | Save output to file | - |
| `-timeout <sec>` | HTTP request timeout in seconds | 10 |
| `-thread <num>` | Number of concurrent threads | 5 |
| `-exclude <exts>` | Exclude file extensions (comma-separated) | - |
| `-s` | Silent mode (no banner/summary) | false |
| `-v` | Verbose mode (detailed errors) | false |
| `-h` | Show help message | false |

---

## 🎯 Examples

### 1. Basic Secret Scanning

```bash
# Scan a single JavaScript file
jsleuth -u https://example.com/static/app.js -secret

# Scan with verbose output
jsleuth -u https://example.com/app.js -secret -v
```

### 2. Batch Scanning from File

```bash
# Create urls.txt with JavaScript URLs
echo "https://example.com/js/main.js" > urls.txt
echo "https://example.com/static/bundle.js" >> urls.txt

# Scan all URLs
jsleuth -f urls.txt -secret -links -thread 10
```

### 3. Pipeline Input

```bash
# Using waybackurls
waybackurls example.com | grep -E '\.js$' | jsleuth -secret -s

# Using gau
echo "example.com" | gau | grep '\.js' | jsleuth -secret -links

# Using hakrawler
echo "https://example.com" | hakrawler -js | jsleuth -secret
```

### 4. Multi-Mode Scanning

```bash
# Extract secrets, links, and subdomains
jsleuth -u https://example.com/app.js -custom secret,links,subs

# All modes with output to file
jsleuth -f urls.txt -custom secret,links,path,subs -o results.txt
```

### 5. Advanced Usage

```bash
# High-performance scan with 20 threads
jsleuth -f urls.txt -secret -links -thread 20 -timeout 15

# Exclude image and font files
jsleuth -f urls.txt -secret -exclude png,jpg,svg,woff,woff2,ttf

# Silent mode for automation
jsleuth -f urls.txt -secret -s -o secrets.txt
```

### 6. Bug Bounty Workflow

```bash
# Complete reconnaissance workflow
subfinder -d example.com -silent | \
httpx -silent -mc 200 | \
waybackurls | \
grep -E '\.js$' | \
sort -u | \
jsleuth -secret -links -thread 15 -o findings.txt
```

---

## 🔐 Detection Patterns

JSleuth includes **180+ carefully crafted regex patterns** organized into 26 categories:

### Cloud Service Tokens
- AWS (Access Key, Secret Key)
- Google Cloud (API Key, Service Account)
- Azure (Client Secret, SAS Token, Storage Keys)
- DigitalOcean, Heroku

### API Keys & Tokens
- Stripe (Live, Publishable, Restricted Keys)
- Twilio (Account SID, Auth Token)
- SendGrid, Mailgun, Slack, Discord
- GitHub (PAT, OAuth, App Tokens)
- GitLab (Personal, Runner Tokens)

### OAuth & Authentication
- OAuth Client Secrets & IDs
- Refresh Tokens
- Bearer Tokens
- JWT Tokens
- Authorization Headers

### Payment Gateways
- Stripe, Square, PayPal
- Braintree, Razorpay

### Database Credentials
- MongoDB, PostgreSQL, MySQL, Redis URIs
- Supabase, Elasticsearch, CouchDB
- JDBC Connection Strings

### Modern Cloud Platforms
- Vercel, Netlify, Fastly
- Contentful, Prismic
- Mapbox, Cloudinary

### CI/CD & DevOps
- CircleCI, Travis CI, Jenkins
- Docker Hub, NPM, PyPI tokens
- Kubernetes Service Accounts
- HashiCorp Vault

### Communication Platforms
- Slack Webhooks & Tokens
- Discord Webhooks
- Microsoft Teams Webhooks
- Telegram Bot Tokens

### Monitoring & Analytics
- Datadog, Grafana, PagerDuty
- Sentry DSN, Splunk
- New Relic, Mixpanel

### Security Patterns
- Private Keys (RSA, OpenSSH, PGP, EC, DSA)
- SSH Keys & Fingerprints
- Certificates (PEM)
- Encryption Keys (AES)

### JavaScript-Specific
- localStorage.setItem() tokens
- sessionStorage.setItem() tokens
- Package.json auth tokens
- NPM registry tokens

### Internal Infrastructure
- Private IP Addresses (10.x, 172.x, 192.x)
- Dev/Staging URLs
- Internal Domains (.internal, .local, .private)

[View complete pattern list](patterns.go)

---

## 📊 Output

### Console Output

```
╔═══════════════════════════════════════════════╗
║   JSleuth v2.0.1                              ║
║   Developed by github.com/vijay922            ║
╚═══════════════════════════════════════════════╝

[+] Loaded 180/180 secret detection patterns
[+] Starting scan on 5 target(s) with 5 thread(s)

[URL 1/5] https://example.com/app.js
  [AWS ACCESS KEY ID] AKIAIOSFODNN7EXAMPLE
  [Link-Absolute #1] https://example.com/api/v1/users
  [STRIPE LIVE KEY] sk_live_4eC39HqLyjWDarjtT1zdp7dc

[URL 2/5] https://example.com/bundle.js
  [Subdomain #1] api.example.com
  [Path-Absolute #1] /etc/config/secrets.json

════════════════════════════════════════════════════════════
[Summary]
────────────────────────────────────────────────────────────
  Total URLs Processed:  5
  Links Found:           12
  Paths Found:           8
  Subdomains Found:      3
  Secrets Found:         7
  Errors:                0
  Time Taken:            0m 15s
  Output Saved:          results.txt
════════════════════════════════════════════════════════════
```

### File Output (Plain Text)

When using `-o` flag, output is saved without ANSI colors:

```
[URL 1/5] https://example.com/app.js
  [AWS ACCESS KEY ID] AKIAIOSFODNN7EXAMPLE
  [Link-Absolute #1] https://example.com/api/v1/users
  [STRIPE LIVE KEY] sk_live_4eC39HqLyjWDarjtT1zdp7dc
```

---

## ⚡ Performance

### Benchmarks

| URLs | Threads | Patterns | Time | Memory |
|------|---------|----------|------|--------|
| 100 | 5 | 180 | ~45s | ~50MB |
| 500 | 10 | 180 | ~3m 20s | ~120MB |
| 1000 | 20 | 180 | ~5m 30s | ~200MB |

### Optimization Tips

1. **Increase threads** for large-scale scans: `-thread 20`
2. **Exclude unnecessary files**: `-exclude png,jpg,svg,woff`
3. **Use silent mode** for automation: `-s`
4. **Adjust timeout** based on network: `-timeout 15`

---

## 🛠️ Configuration

### Input File Format

Create a text file with one URL per line:

```
# JavaScript files from example.com
https://example.com/static/js/main.js
https://example.com/assets/bundle.js
https://api.example.com/v1/client.js

# Comments are supported (lines starting with #)
# Blank lines are ignored
```

### Custom Pattern Addition

To add your own patterns, edit `patterns.go`:

```go
var RegexPatterns = map[string]string{
    // Add your custom pattern
    "My Custom Token": `custom_[a-zA-Z0-9]{32}`,
    
    // ... existing patterns
}
```

Then rebuild:

```bash
go build -o jsleuth main.go patterns.go
```

---

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

### Adding New Patterns

1. Fork the repository
2. Add patterns to `patterns.go` with proper categorization
3. Test patterns against known samples
4. Submit a pull request with:
   - Pattern name
   - Regex pattern
   - Example matches
   - Service/platform documentation link

### Reporting Issues

- **Bug Reports**: Include Go version, OS, command used, and error message
- **False Positives**: Provide the pattern name and example that triggered it
- **Feature Requests**: Describe use case and expected behavior

### Pattern Contribution Guidelines

- Use descriptive pattern names
- Include category comments
- Test for false positives
- Provide sample matches
- Document token format specifics

---

## ⚠️ Disclaimer

**JSleuth** is designed for **ethical security research and authorized testing only**.

### Legal Notice

- ✅ **Authorized Use**: Bug bounty programs, penetration testing with permission, security audits
- ❌ **Unauthorized Use**: Scanning targets without explicit permission is illegal

### Responsible Disclosure

If you discover vulnerabilities using JSleuth:

1. Report to the organization's security team immediately
2. Do NOT exploit or publicly disclose before remediation
3. Follow responsible disclosure guidelines
4. Allow reasonable time for fixes

### User Responsibility

By using JSleuth, you agree to:
- Only scan systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Use findings ethically and responsibly
- Not use for malicious purposes

**The author is not responsible for misuse of this tool.**

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

```
MIT License

Copyright (c) 2025 Vijay Kumar Chippa

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
```

---

## 👨‍💻 Author

**Vijay Kumar Chippa**

- GitHub: [@vijay922](https://github.com/vijay922)
- Twitter: [@vijay922](https://twitter.com/vijay922)
- LinkedIn: [vijay-kumar-chippa](https://www.linkedin.com/in/vijay-kumar-chippa-89111b49)
- Role: Security Researcher | Bug Bounty Hunter

### Other Projects

Check out my other security tools:

- [Bug-Bounty-Scripts](https://github.com/vijay922/Bug-Bounty-Scripts) - Collection of bug bounty automation scripts
- [SSL-Certificate-Scanner](https://github.com/vijay922/SSL-Certificate-Scanner) - SSL/TLS certificate analysis tool
- [SQL-Injection-Scanner](https://github.com/vijay922/SQL-Injection-Scanner) - SQLi vulnerability detection
- [RCE-Scanner](https://github.com/vijay922/RCE-Scanner) - Remote Command Execution scanner
- [Linux-LFI](https://github.com/vijay922/Linux-LFI) - Path traversal vulnerability detector
- [URL-Processor](https://github.com/vijay922/URL-Processor) - URL extraction and processing tool

---

## 🌟 Star History

If you find JSleuth useful, please consider giving it a star ⭐

[![Star History Chart](https://api.star-history.com/svg?repos=vijay922/JSleuth&type=Date)](https://star-history.com/#vijay922/JSleuth&Date)

---

## 📈 Roadmap

- [ ] JSON output format
- [ ] HTML report generation
- [ ] Entropy-based secret detection
- [ ] Integration with secret validation APIs
- [ ] Browser extension support
- [ ] Machine learning-based pattern detection
- [ ] WebSocket URL extraction
- [ ] GraphQL endpoint discovery

---

## 🙏 Acknowledgments

- Pattern database inspired by [TruffleHog](https://github.com/trufflesecurity/trufflehog), [GitLeaks](https://github.com/gitleaks/gitleaks), and [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db)
- Community contributions from bug bounty hunters worldwide
- Security researchers who responsibly disclosed pattern improvements

---

## 💬 Community

Join the discussion:

- Report issues: [GitHub Issues](https://github.com/vijay922/JSleuth/issues)
- Feature requests: [GitHub Discussions](https://github.com/vijay922/JSleuth/discussions)
- Twitter: [@vijay922](https://twitter.com/vijay922)

---

<div align="center">

**Made with ❤️ by [Vijay Kumar Chippa](https://github.com/vijay922)**

If JSleuth helped you find a bug bounty, consider [buying me a coffee](https://www.buymeacoffee.com/vijay922) ☕

</div>
