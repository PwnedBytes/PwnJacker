# 🔍 PwnJacker

[![Go Version](https://img.shields.io/github/go-mod/go-version/PwnedBytes/PwnJacker)](https://golang.org/)
[![License](https://img.shields.io/github/license/PwnedBytes/PwnJacker)](LICENSE)

**PwnJacker** is an advanced subdomain hijacking vulnerability checker written in Go. It goes beyond basic CNAME takeover detection by incorporating email security analysis, cloud service misconfigurations, wildcard DNS detection, and supply‑chain risk assessment. Designed for ethical hackers and bug bounty hunters, PwnJacker runs efficiently on Termux (Android) and features a real‑time web dashboard.

---

## 📖 Table of Contents

- [Features](#features)
  - [Core Detection](#core-detection)
  - [Advanced Capabilities](#advanced-capabilities)
  - [Dashboard & Reporting](#dashboard--reporting)
- [Why PwnJacker?](#why-pwnjacker)
  - [Comparison with Existing Tools](#comparison-with-existing-tools)
- [Installation](#installation)
  - [On Termux (Android)](#on-termux-android)
  - [On Linux / macOS](#on-linux--macos)
  - [Using Docker](#using-docker)
- [Usage](#usage)
  - [Basic Scan](#basic-scan)
  - [Advanced Options](#advanced-options)
  - [Examples](#examples)
- [Configuration](#configuration)
  - [Configuration File](#configuration-file)
  - [Environment Variables](#environment-variables)
- [Output Formats](#output-formats)
- [Web Dashboard](#web-dashboard)
- [Fingerprint Database](#fingerprint-database)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

### Core Detection
- **CNAME Takeover** – 50+ service fingerprints (AWS S3, GitHub Pages, Azure, Heroku, etc.).
- **NXDOMAIN Detection** – Identifies unresolving domains that can be registered.
- **Wildcard DNS** – Detects wildcard configurations and their security implications.
- **Email Security** – SPF, DKIM, DMARC and MX record analysis (including vulnerable includes).
- **Cloud Service Misconfigurations** – AWS, Azure, GCP, DigitalOcean specific checks.

### Advanced Capabilities
- **Historical DNS Analysis** – Tracks DNS changes over time (requires external APIs).
- **Supply‑Chain Risk** – Discovers third‑party dependencies (JS includes, iframes) that may be hijackable.
- **Intelligent Wordlist Generation** – Creates target‑specific subdomain wordlists.
- **Checkpoint / Resume** – Saves scan progress; resumes after interruption.
- **Rate Limiting & Polite Scanning** – Avoids being blocked by target services.

### Dashboard & Reporting
- **Real‑time Web Dashboard** – Live updates via WebSocket, charts, and filtering.
- **Multiple Output Formats** – JSON, Markdown, CSV, HTML, HackerOne, Bugcrowd.
- **Exportable Reports** – Generate professional reports for bug bounty submissions.

---

## 🎯 Why PwnJacker?

PwnJacker is not just another subdomain takeover scanner. It was built from the ground up to address the limitations of existing tools, providing broader coverage, smarter detection, and a seamless user experience – even on low‑end devices like Android phones via Termux.

### Comparison with Existing Tools

| Feature | PwnJacker | subjack | subover | nuclei (takeover) |
|---------|-----------|---------|---------|-------------------|
| **CNAME Fingerprints** | 50+ (and growing) | ~20 | ~15 | ~30 |
| **Email Security Checks** | ✅ SPF/DKIM/DMARC/MX | ❌ | ❌ | ❌ |
| **Wildcard Detection** | ✅ | ❌ | ❌ | ❌ |
| **Cloud Service Checks** | ✅ (AWS, Azure, GCP, DO) | ❌ | ❌ | Limited |
| **Web Dashboard** | ✅ (real‑time, WebSocket) | ❌ | ❌ | ❌ |
| **Checkpoint / Resume** | ✅ | ❌ | ❌ | ❌ |
| **Termux Optimized** | ✅ | ❌ | ❌ | ❌ |
| **Multiple Output Formats** | ✅ (JSON, MD, CSV, HTML, H1, BC) | ❌ (JSON only) | ❌ | ✅ (JSON, Markdown) |
| **False Positive Reduction** | ✅ (multi‑stage verification) | ❌ (high) | ❌ | ❌ |
| **Community Fingerprint Updates** | ✅ (YAML, no recompile) | ❌ | ❌ | ❌ |
| **Intelligent Wordlist Generation** | ✅ | ❌ | ❌ | ❌ |
| **Supply‑Chain Risk Analysis** | ✅ | ❌ | ❌ | ❌ |

**Key Advantages:**
- **Comprehensive Coverage**: Detects not only classic CNAME takeovers but also email‑related vulnerabilities and cloud misconfigurations.
- **Resource‑Efficient**: Optimized for Termux; runs smoothly on budget Android phones with adaptive concurrency and battery‑aware scanning.
- **Real‑Time Visibility**: The web dashboard provides instant feedback, making it easy to monitor scans and triage findings.
- **Bug Bounty Ready**: Outputs reports formatted for HackerOne and Bugcrowd, saving you time when submitting findings.
- **Evolving Fingerprints**: Fingerprints are stored in YAML files and can be updated without recompiling – the community can contribute new services easily.

---

## 📦 Installation

### On Termux (Android)
```bash
pkg update && pkg upgrade
pkg install golang git
git clone https://github.com/PwnedBytes/PwnJacker.git
cd PwnJacker
./scripts/install-termux.sh
```

### On Linux / macOS

```bash
# Clone the repository
git clone https://github.com/PwnedBytes/PwnJacker.git
cd PwnJacker

# Build (see Makefile for options)
make build

# (Optional) Install to $GOPATH/bin
make install
```

### Using Docker

```bash
docker build -t pwnjacker .
docker run --rm -v $(pwd)/output:/home/pwnjacker pwnjacker -l /path/to/domains.txt
```

---

## 🚀 Usage

Basic Scan

```bash
pwnjacker -l subdomains.txt -o results.json
```

Advanced Options

Flag Description
-l File containing list of subdomains (one per line)
-o Output file (default: results.json)
-t Number of concurrent threads (default: CPU cores)
--timeout HTTP timeout in seconds (default: 10)
--check-email Enable email security checks (SPF/DKIM/DMARC)
--deep Deep scan – more thorough checks (slower)
--dashboard Start web dashboard on specified port (e.g., :8080)
--resume Resume scan from checkpoint file
--format Output format: json, markdown, csv, html, hackerone, bugcrowd
-v Verbose output

Examples

```bash
# Scan with email checks and start dashboard
pwnjacker -l targets.txt --check-email --dashboard :8080

# Deep scan with custom thread count, output to HTML
pwnjacker -l big-list.txt -t 20 --deep --format html -o report.html

# Resume interrupted scan
pwnjacker --resume autosave.json -o results.json
```

---

## ⚙️ Configuration

Configuration File

PwnJacker reads configuration from $HOME/.config/pwnjacker/config.yaml (or a custom path via --config).
Example config.yaml:

```yaml
scanner:
  threads: 10
  timeout: 10
  retries: 3

detectors:
  email:
    enabled: true
    spf: true
    dkim: true
    dmarc: true
  cloud:
    aws: true
    azure: true
    gcp: true
    digitalocean: true

dashboard:
  port: ":8080"
  refresh_interval: 5

fingerprints:
  auto_update: true
  update_url: "https://raw.githubusercontent.com/PwnedBytes/PwnJacker/main/fingerprints.yaml"
```

Environment Variables

· PWNHOME – Override the configuration directory.
· PWNCACHE – Set cache directory (default: $HOME/.cache/pwnjacker).

---

## 📊 Output Formats

Format Description
json Full structured data for further processing.
markdown Human‑readable report with evidence.
csv Tabular format for spreadsheets.
html Self‑contained HTML report (no external deps).
hackerone Markdown ready for HackerOne submission.
bugcrowd Text format aligned with Bugcrowd guidelines.

---

## 🌐 Web Dashboard

When launched with ```--dashboard :8080```, PwnJacker starts a lightweight HTTP server. Open ```http://localhost:8080``` to view:

· Live scan progress and statistics.
· Real‑time findings (via WebSocket).
· Filterable results table.
· Charts for severity and service distribution.

The dashboard is fully responsive and works on mobile devices.

---

## 🧠 Fingerprint Database

Fingerprints are stored as YAML files in ```configs/fingerprints.yaml``` (and split into ```cloud.yaml```, ```saas.yaml```, ```email.yaml```).
You can extend the database by adding new services following the existing structure.
Fingerprints are automatically loaded at startup and can be updated via:

```bash
./scripts/update-fingerprints.sh
```

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a feature branch (```git checkout -b``` feature/amazing).
3. Commit your changes (```git commit -m``` 'Add amazing feature').
4. Push to the branch (```git push origin``` feature/amazing).
5. Open a Pull Request.

See ```CONTRIBUTING.md``` for detailed guidelines.

---

## 📄 License

This project is licensed under the MIT License – see the LICENSE file for details.

---

PwnJacker – Created by PwnedBytes.
For ethical hacking and security research only.
