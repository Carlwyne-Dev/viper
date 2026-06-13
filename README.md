<div align="center">

```
 ██╗   ██╗██╗██████╗ ███████╗██████╗
 ██║   ██║██║██╔══██╗██╔════╝██╔══██╗
 ██║   ██║██║██████╔╝█████╗  ██████╔╝
 ╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
  ╚████╔╝ ██║██║     ███████╗██║  ██║
   ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**we bite.**

A precision recon & security toolkit.

![Python](https://img.shields.io/badge/python-3.10%2B-green?style=flat-square)
![Version](https://img.shields.io/badge/version-1.0.0-green?style=flat-square)
![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-green?style=flat-square)

</div>

---

## Philosophy

Viper is **recon-first**. It does less than most tools and does it better.

- **Signal over noise.** Every output line earns its place.
- **Fast by default.** Auto-tunes scan timeout based on measured latency.
- **Opinionated.** `viper bite` does the right thing. No flags required.
- **Precision over spam.** `CRIT` means CRIT.
- **Memory.** Viper remembers every scan. `viper diff` shows what changed.

> *Built to feel like a precision instrument, not a noisy toy.*

---

## Install

```bash
git clone https://github.com/yourusername/viper.git
cd viper
pip install -e .

# Optional: richer DNS + WHOIS support
pip install -e ".[full]"
```

---

## Docker

Run Viper in a container — no dependency hell, guaranteed to work on any system:

```bash
# Build the image
docker build -t viper:latest .

# Run Viper
docker run -it viper:latest
```

Works identically on Windows, Mac, and Linux. No Python version conflicts, no missing dependencies.

---

## Fangs

| Command | What it does |
|---------|-------------|
| `viper bite target.com` | Fast recon: scan + DNS + subs + vuln hints |
| `viper bite target.com --all` | + Web Fang: tech stack, paths, SSL, headers |
| `viper venom target.com` | Full assault, auto-saves HTML + JSON report |
| `viper web target.com` | Web fingerprint, sensitive paths, SSL audit |
| `viper fang target.com` | Focused port scan |
| `viper recon target.com` | DNS records + subdomain enumeration |
| `viper osint johndoe --social` | Social media footprint |
| `viper crack <hash>` | Identify + crack password hashes |
| `viper diff target.com` | Compare last two scans — what changed? |
| `viper history target.com` | Full scan history |
| `viper report scan.json` | Generate HTML report |

---

## What it looks like

```
──  BITE FANG  google.com ──────────────────────────────────
[VIPER]  Target locked → google.com
[INFO]   Latency tuned timeout → 0.30s per port

──  PORT FANG  google.com ──────────────────────────────────
[SCAN]   Scanning 1-1024...

  PORT      STATE   SERVICE
  ──────    ──────  ────────────
  80        OPEN    HTTP
  443       OPEN    HTTPS

  2 open ports  ·  1.2s

──  DNS FANG  google.com ───────────────────────────────────
  A       142.250.80.46
  MX      10 smtp.google.com.
  NS      ns1.google.com.
  TXT     "v=spf1 include:_spf.google.com ~all"

  11 records  ·  0.4s

──  DNS FANG  subdomains · google.com ──────────────────────
[FOUND]  admin.google.com    172.217.26.78
[FOUND]  vault.google.com    74.125.204.118
[FOUND]  api.google.com      142.251.8.106

  15 subdomains found  ·  1.8s
```

```
viper diff google.com

──  DIFF  google.com ────────────────────────────────────────
  prev  2026-05-21
  curr  2026-05-28
  delta +40 risk

──  NEW FINDINGS ───────────────────────────────────────────
  +  [HIGH]    Port 8080 open     HTTP-Alt
  +  [MED]     Missing CSP        port 80

──  CLOSED ─────────────────────────────────────────────────
  -  [LOW]     Port 21 open       FTP

  +2 new  -1 closed  ~0 changed  47 stable
```

---

## Usage

### The default move
```bash
viper bite google.com
viper bite google.com --all          # includes web analysis
viper bite google.com --save out.json
viper bite google.com --silent --json | jq .ports
```

### Full assault
```bash
viper venom google.com
viper venom google.com --out ./reports
```

### Web intelligence
```bash
viper web google.com
viper web google.com --save web.json
```

### Port scan
```bash
viper fang 10.0.0.1
viper fang 10.0.0.1 -p 1-65535
viper fang 10.0.0.1 -p 22,80,443 --threads 300
```

### DNS + subdomains
```bash
viper recon google.com
viper recon google.com --whois
```

### OSINT
```bash
viper osint johndoe --social
viper osint t --email john doe company.com
```

### Hash cracking
```bash
viper crack 5f4dcc3b5aa765d61d8327deb882cf99
viper crack <hash> -w /usr/share/wordlists/rockyou.txt
viper crack <hash> --identify
```

### Intelligence (scan history + diff)
```bash
viper bite google.com            # auto-saves to ~/.viper/history/
viper bite google.com            # scan again later
viper diff google.com            # what changed?
viper history google.com         # all past scans
viper targets                    # all tracked targets
```

### Reports
```bash
viper bite google.com --save scan.json
viper report scan.json -o report.html
```

### Config
```bash
viper config --show
viper config --init
viper config --set scan.threads 200
viper config --set scan.timeout 0.3
viper config --set scan.ports 1-65535
```

---

## Architecture

```
viper/
├── cli.py              # Commands — voice of the tool
├── core/
│   ├── models.py       # Unified Finding + ScanResult
│   ├── history.py      # Scan persistence (~/.viper/history/)
│   ├── diff.py         # Comparison engine
│   ├── latency.py      # Network-aware timeout tuning
│   ├── config.py       # Typed config (~/.viper/config.json)
│   └── errors.py       # Graceful failures, no tracebacks
├── bite/
│   ├── quick.py        # viper bite — fast default flow
│   └── deep.py         # viper venom — full assault
├── modules/            # Raw capability. No rendering.
│   ├── scanner.py      # Threaded port scanner
│   ├── recon.py        # DNS + concurrent subdomain enum
│   ├── vuln.py         # Banner grab + CVE signatures
│   ├── web.py          # Web fingerprint + path check
│   ├── osint.py        # Email + social footprint
│   └── crack.py        # Hash ID + wordlist crack
└── output/
    ├── terminal.py     # All rendering. One place.
    └── report.py       # HTML + JSON export
```

**The key rule:** `modules/` never prints anything. `output/terminal.py` owns every line that hits the screen. Change the design, change one file.

---

## Workflow

```bash
# Recon a target
viper bite target.com --all --save $(date +%F)-target.json

# Generate report
viper report $(date +%F)-target.json -o report.html

# Come back next week
viper bite target.com

# See what changed
viper diff target.com
```

---

## Requirements

- Python 3.10+
- `click>=8.0`
- `rich>=13.0`
- Optional: `dnspython`, `python-whois`

---

## Disclaimer

> For authorized use only. Only scan systems you own or have explicit permission to test. You are responsible for how you use this tool.

---

<div align="center">

*a quiet tool that actually is.*

</div>
