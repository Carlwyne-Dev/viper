"""
bite/deep.py — `viper venom`
Full assault. Includes Web Fang. Auto-tunes timeout. Saves HTML + JSON.
"""

import json
import datetime
from pathlib import Path
from dataclasses import asdict

from viper.core import errors, jsonout
from viper.core.config import load as load_config
from viper.core.latency import tune_timeout
from viper.modules import scanner, recon, vuln
from viper.output import terminal as out
from viper.output import report


def run(target: str, output_dir: str = ".", json_mode: bool = False):
    if json_mode:
        jsonout.enable()
        out.set_silent(True)

    cfg      = load_config()
    ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    out.rule("VENOM", target)
    out.tag("viper", f"Full assault → [cyan]{target}[/cyan]")
    out.blank()

    try:
        ip = errors.resolve(target)
    except errors.ResolveError as e:
        errors.handle(e); return

    # Auto-tune
    auto_timeout = tune_timeout(ip)
    out.tag("info", f"Resolved → [target]{ip}[/target]  [dim]·  timeout tuned to {auto_timeout:.2f}s[/dim]")
    out.blank()

    data = {"target": target, "ip": ip, "ports": [], "dns": {},
            "subs": [], "vulns": [], "web": {}, "whois": {}}

    # ── 1. Full port scan ─────────────────────────────────────────────────
    out.rule("PORT FANG", "1-65535")
    out.tag("scan", "Full port scan — all 65535 ports...")
    out.blank()

    port_list = scanner.parse_ports("1-65535")
    with out.Timer() as t:
        if not json_mode:
            with out.scan_progress(len(port_list)) as progress:
                task = progress.add_task("full scan", total=len(port_list))
                open_ports = scanner.scan(
                    ip, "1-65535", auto_timeout, cfg.scan.threads,
                    on_progress=lambda: progress.advance(task),
                )
        else:
            open_ports = scanner.scan(ip, "1-65535", auto_timeout, cfg.scan.threads)

    data["ports"] = [asdict(p) for p in open_ports]
    out.ports_table(open_ports)
    flagged = sum(1 for p in open_ports if p.flagged)
    out.summary(len(open_ports), "open ports", t.seconds, flagged)

    # ── 2. Recon ──────────────────────────────────────────────────────────
    out.blank()
    out.rule("DNS FANG", target)
    out.tag("scan", "DNS records + WHOIS + subdomains...")
    out.blank()

    with out.Timer() as t:
        dns_result = recon.dns(target)
        whois_data = recon.whois(target)
        subs       = recon.subdomains(target, threads=50)

    data["dns"]   = asdict(dns_result)
    data["whois"] = whois_data
    data["subs"]  = [asdict(s) for s in subs]

    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        for val in getattr(dns_result, rtype, []):
            if not json_mode:
                out.dns_line(rtype, val)

    out.blank()
    for s in subs:
        out.tag("found", f"[target]{s.subdomain}[/target]  [dim]{s.ip}[/dim]")
    out.summary(len(subs), "subdomains", t.seconds)

    # ── 3. Vuln scan ──────────────────────────────────────────────────────
    out.blank()
    out.rule("VENOM FANG", target)
    out.tag("scan", "Banner grab + CVE matching...")
    out.blank()

    with out.Timer() as t:
        with out.console.status("  [dim]analyzing...[/dim]", spinner="dots"):
            probe_ports = [p.port for p in open_ports] or None
            banners, vulns_found, missing = vuln.scan(ip, ports=probe_ports, timeout=3.0)

    data["vulns"] = [asdict(v) for v in vulns_found]

    if vulns_found:
        for v in sorted(vulns_found, key=lambda x: out.SEVERITY_RANK.get(x.severity, 9)):
            out.finding(v.severity, v.cve, v.desc)
    for m in missing:
        out.finding("LOW", f"Missing: {m.header}", f"port {m.port}")
    if not vulns_found and not missing:
        out.tag("info", "No vulnerability signatures matched.")

    crits = sum(1 for v in vulns_found if v.severity == "CRIT")
    out.summary(len(vulns_found) + len(missing), "findings", t.seconds, flagged=crits)

    # ── 4. Web Fang ───────────────────────────────────────────────────────
    out.blank()
    out.rule("WEB FANG", target)
    out.tag("scan", "Tech fingerprint, paths, SSL, headers...")
    out.blank()

    from viper.modules.web import scan as web_scan
    with out.Timer() as t:
        with out.console.status("  [dim]analyzing...[/dim]", spinner="dots"):
            web = web_scan(target, timeout=6.0)

    if web.status > 0:
        out.tag("info", f"Status [white]{web.status}[/white]  [dim]{web.url}[/dim]")
        if web.title:
            out.tag("info", f"Title  [white]{web.title[:72]}[/white]")
        out.blank()

        seen = set()
        for tech in web.tech:
            if tech.name not in seen:
                seen.add(tech.name)
                out.tag("found", f"[white]{tech.name}[/white]  [dim]{tech.source}[/dim]")

        if web.ssl:
            if web.ssl.expired:
                out.finding("CRIT", f"Certificate EXPIRED ({web.ssl.expires})")
            elif web.ssl.expiring_soon:
                out.finding("HIGH", f"Expires in {web.ssl.days_left} days ({web.ssl.expires})")
            else:
                out.tag("info", f"TLS    [white]{web.ssl.tls_version}[/white]  [dim]expires {web.ssl.expires} ({web.ssl.days_left}d)[/dim]")

        out.blank()
        for p in web.paths:
            if p.severity in ("CRIT", "HIGH"):
                out.finding(p.severity, p.path, f"HTTP {p.status}")
        for h in sorted(web.headers, key=lambda x: {"HIGH":0,"MED":1,"LOW":2}.get(x.severity,3)):
            out.finding(h.severity, h.header, h.desc)

        web_findings = len([p for p in web.paths if p.severity not in ("INFO","LOW")]) + len(web.headers)
        web_crits    = len([p for p in web.paths if p.severity == "CRIT"])
        out.summary(web_findings, "web findings", t.seconds, flagged=web_crits)
    else:
        out.tag("info", "No HTTP response on port 80 or 443.")

    data["web"] = {
        "url": web.url, "status": web.status, "title": web.title,
        "tech":    [asdict(t) for t in web.tech],
        "paths":   [asdict(p) for p in web.paths],
        "headers": [asdict(h) for h in web.headers],
        "ssl":     asdict(web.ssl) if web.ssl else {},
    }

    # ── 5. Export ─────────────────────────────────────────────────────────
    out.blank()
    out.rule("EXPORT")
    slug      = target.replace(".", "_")
    html_path = out_path / f"viper_{slug}_{ts}.html"
    json_path = out_path / f"viper_{slug}_{ts}.json"

    report.render_html(data, str(html_path))
    report.render_json(data, str(json_path))
    out.saved(str(html_path))
    out.saved(str(json_path))
    out.blank()

    if json_mode:
        jsonout.merge(data)
        jsonout.flush()

    out.set_silent(False)
    jsonout.disable()
