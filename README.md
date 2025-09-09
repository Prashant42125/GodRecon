# 🛡️ GodRecon - Reconnaissance & Vulnerability Scanning Tool

![Banner](https://img.shields.io/badge/GodRecon-Reconnaissance%20Framework-blue)

<img src="https://github.com/Prashant42125/GodRecon/blob/main/GodRecon.png?raw=true" width="700px" height="500px" alt="godrecon.png" >

A comprehensive bash-based reconnaissance and vulnerability scanning framework for penetration testers and security researchers. 🚀

## ✨ Features

- **🔍 Passive Reconnaissance**: WHOIS lookup, DNS enumeration, subdomain discovery, technology detection
- **⚡ Active Reconnaissance**: Directory brute-forcing, port scanning, URL extraction, parameter discovery
- **📊 Vulnerability Scanning**: Nuclei scans, SSL/TLS testing, security headers analysis, CORS misconfiguration testing
- **🎯 Multiple Target Support**: Single domain, wildcard domains, or domain lists
- **🔔 Notification System**: Optional alerts for scan completion
- **🔄 Continuous Scanning**: Massive mode for ongoing monitoring
- **📁 Organized Output**: Structured results with detailed reporting

## 📋 Prerequisites

### 🛠️ Required Tools
```bash
# Subdomain enumeration
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Network mapping
go install -v github.com/owasp-amass/amass/v3/...@master

# HTTP probing
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Vulnerability scanning
go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Technology detection
sudo apt install whatweb

# Screenshot tool
# Download from: https://github.com/michenriksen/aquatone

# Directory brute-forcing
git clone https://github.com/maurosoria/dirsearch.git

# Port scanning
sudo apt install nmap

# URL extraction
go install github.com/lc/gau/v2/cmd/gau@latest
```

🔧 Optional Tools
```bash
# SSL/TLS testing
git clone https://github.com/drwetter/testssl.sh.git

# Security headers check
pip install shcheck

# CORS testing
git clone https://github.com/s0md3v/Corsy.git
```
🚀 Installation
Clone the repository and Run script:

```bash
git clone https://github.com/Prashant42125/GodRecon.git
cd GodRecon
chmod +x GodRecon.sh
```

🎯 Usage
```bash
./GodRecon.sh [-d domain.com] [-w domain.com] [-l domains.txt] [-a] [-p] [-x] [-r] [-v] [-m] [-n] [-h]
```

🎯 Target Options
```bash
-d domain.com - Target domain 🎯
-w domain.com - Wildcard domain (for massive mode) 🌐
-l list.txt - File containing list of domains 📋

```
⚙️ Mode Options
```bash
-a, --all - Full reconnaissance and vulnerability scanning 🔍⚡📊
-p, --passive - Passive reconnaissance only 🔍
-x, --active - Active reconnaissance only ⚡
-r, --recon - Both active and passive reconnaissance 🔍⚡
-v, --vuln - Vulnerability scanning only 📊
-m, --massive - Continuous massive scanning 🔄
```
🔔 Extra Options
```bash
-n, --notify - Enable notifications 🔔
-h, --help - Show help message ❓
```

📝 Examples
Full comprehensive scan:

```bash
./GodRecon.sh -d example.com -a
Passive reconnaissance on multiple domains:
```
```bash
./GodRecon.sh -l domains.txt -p
Vulnerability scan with notifications:
```
```bash
./GodRecon.sh -d example.com -v -n
Continuous monitoring:
```

```bash
./GodRecon.sh -w example.com -m
Active reconnaissance only:
```

```bash
./GodRecon.sh -d example.com -x
```
📁 Output Structure
The tool creates organized output directories:
```bash
text
targets/
└── example.com/
    ├── passive_recon/          🔍
    │   ├── whois.txt
    │   ├── subdomains.txt
    │   ├── live_subdomains.txt
    │   ├── whatweb.txt
    │   └── screenshots/        📸
    ├── active_recon/           ⚡
    │   ├── dirsearch.txt
    │   ├── nmap.txt
    │   ├── js_urls.txt
    │   └── parameters.txt
    └── vulnerability_scan/     📊
        ├── nuclei_results.txt
        ├── ssl_test.txt
        ├── security_headers.txt
        └── cors_test.txt
```

🧑‍💻 Author Prashant Swami
```bash
🔗 LinkedIn : https://www.linkedin.com/in/prashant-s-swami
```
