# Changelog

All notable changes to Viper are documented here.

---

## [1.0.0] — 2026-05-28 — First blood.

### Added
- `viper bite` — fast recon: port scan + DNS + subdomains + vuln hints. Auto-tunes timeout based on target latency.
- `viper venom` — full assault: all 65535 ports + complete recon + Web Fang + auto-saves HTML & JSON report.
- `viper web` — Web Fang: tech stack fingerprint, 30+ sensitive path checks, SSL/TLS analysis, security header audit.
- `viper fang` — focused port scan with configurable range, threads, and timeout.
- `viper recon` — DNS records + concurrent subdomain enumeration.
- `viper osint` — email pattern generation + 10-platform social media footprint.
- `viper crack` — hash identification and wordlist cracking. Supports MD5, SHA1, SHA256, SHA384, SHA512. Ships with 500-word built-in list.
- `viper diff` — compare the two most recent scans for a target. Shows new findings, closed findings, changed severity, and risk delta.
- `viper history` — scan history per target, stored at `~/.viper/history/`.
- `viper targets` — list all tracked targets.
- `viper report` — generate dark-themed HTML or JSON report from any saved scan file.
- `viper config` — manage `~/.viper/config.json` with typed defaults.
- Unified `Finding` model — every finding across every fang speaks one language.
- Auto-latency tuning — measures RTT to target before scanning, tunes timeout automatically.
- `--json` flag on every command — machine-readable output for piping.
- `--silent` flag — suppress all output except findings.
- VIPER UI/UX design system — venom green identity, severity hierarchy, fang vocabulary.

### Architecture
- `modules/` never prints. `output/terminal.py` owns all rendering.
- `core/models.py` — unified Finding + ScanResult dataclasses.
- `core/history.py` — automatic scan persistence.
- `core/diff.py` — comparison engine with stable finding keys.
- `core/latency.py` — network-aware timeout tuning.
- `output/report.py` — dark-themed HTML report renderer.

---

## [0.2.0] — Internal

- Web Fang added
- Silent mode + JSON output mode
- Concurrent subdomain enumeration (50 threads)
- Venom green design system

## [0.1.0] — Internal

- Initial scaffold: scan, recon, osint, crack, report
- Basic CLI with click + rich
