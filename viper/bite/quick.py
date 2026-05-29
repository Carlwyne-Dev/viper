"""
bite/quick.py — `viper bite`
Fast recon: scan + dns + subs + vuln.
--all adds Web Fang to the flow.
--json outputs machine-readable JSON.
Auto-tunes timeout based on measured latency.
"""

import json
from pathlib import Path
from dataclasses import asdict

from viper.core import errors, jsonout
from viper.core.config import load as load_config
from viper.core.latency import tune_timeout
from viper.modules import scanner, recon, vuln
from viper.output import terminal as out


def run(target: str, save: str | None = None, silent: bool = False,
        all_fangs: bool = False, json_mode: bool = False):

    if silent:    out.set_silent(True)
    if json_mode: jsonout.enable(); out.set_silent(True)

    cfg = load_config()

    out.rule("BITE FANG", target)
    out.tag("viper", f"Target locked → [cyan]{target}[/cyan]")
    out.blank()

    # Resolve
    try:
        ip = errors.resolve(target)
    except errors.ResolveError as e:
        errors.handle(e); return

    if ip != target:
        out.tag("info", f"Resolved [dim]{target}[/dim] → [target]{ip}[/target]")

    # Auto-tune timeout
    user_timeout = cfg.scan.timeout
    auto_timeout = tune_timeout(ip)
    timeout = min(user_timeout, auto_timeout) if user_timeout != 0.5 else auto_timeout

    out.tag("info", f"Latency tuned timeout → [white]{timeout:.2f}s[/white] per port")
    out.blank()

    results_data = {"target": target, "ip": ip}

    # ── Port scan ─────────────────────────────────────────────────────────
    out.rule("PORT FANG", target)
    out.tag("scan", f"Scanning [dim]{cfg.scan.ports}[/dim]...")
    out.blank()

    port_list = scanner.parse_ports(cfg.scan.ports)
    with out.Timer() as t:
        if not silent and not json_mode:
            with out.scan_progress(len(port_list)) as progress:
                task = progress.add_task("port scan", total=len(port_list))
                open_ports = scanner.scan(
                    ip, cfg.scan.ports, timeout, cfg.scan.threads,
                    on_progress=lambda: progress.advance(task),
                )
        else:
            open_ports = scanner.scan(ip, cfg.scan.ports, timeout, cfg.scan.threads)

    out.ports_table(open_ports)
    flagged = sum(1 for p in open_ports if p.flagged)
    out.summary(len(open_ports), "open ports", t.seconds, flagged)
    results_data["ports"] = [asdict(p) for p in open_ports]

    # ── DNS ───────────────────────────────────────────────────────────────
    out.blank()
    out.rule("DNS FANG", target)
    out.tag("scan", "Resolving DNS records...")
    out.blank()

    with out.Timer() as t:
        dns_result = recon.dns(target)

    has_dns = False
    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        for val in getattr(dns_result, rtype, []):
            if not silent and not json_mode:
                out.dns_line(rtype, val)
            has_dns = True
    if not has_dns:
        out.warn("No DNS records resolved.")
    total = sum(len(getattr(dns_result, r, [])) for r in ("A","AAAA","MX","NS","TXT"))
    out.summary(total, "records", t.seconds)
    results_data["dns"] = asdict(dns_result)

    # ── Subdomains (concurrent) ───────────────────────────────────────────
    out.blank()
    out.rule("DNS FANG", f"subdomains · {target}")
    out.tag("scan", "Enumerating subdomains...")
    out.blank()

    with out.Timer() as t:
        subs = recon.subdomains(target, threads=50)

    for s in subs:
        out.tag("found", f"[target]{s.subdomain}[/target]  [dim]{s.ip}[/dim]")
    if not subs:
        out.tag("info", "No subdomains resolved.")
    out.summary(len(subs), "subdomains found", t.seconds)
    results_data["subs"] = [asdict(s) for s in subs]

    # ── Vuln hints ────────────────────────────────────────────────────────
    vulns_found = []
    if open_ports:
        out.blank()
        out.rule("VENOM FANG", target)
        out.tag("scan", "Grabbing banners...")
        out.blank()

        with out.Timer() as t:
            with out.console.status("  [dim]analyzing...[/dim]", spinner="dots"):
                banners, vulns_found, missing = vuln.scan(
                    ip, ports=[p.port for p in open_ports], timeout=3.0
                )

        if vulns_found:
            for v in sorted(vulns_found, key=lambda x: out.SEVERITY_RANK.get(x.severity, 9)):
                out.finding(v.severity, v.cve, v.desc)
        for m in missing:
            out.finding("LOW", f"Missing header: {m.header}", f"port {m.port}")
        if not vulns_found and not missing:
            out.tag("info", "No vulnerability signatures matched.")

        crits = sum(1 for v in vulns_found if v.severity == "CRIT")
        out.summary(len(vulns_found) + len(missing), "findings", t.seconds, flagged=crits)
        results_data["vulns"] = [asdict(v) for v in vulns_found]

    # ── Web Fang (--all) ──────────────────────────────────────────────────
    if all_fangs:
        from viper.modules.web import scan as web_scan
        out.blank()
        out.rule("WEB FANG", target)
        out.tag("scan", "Fingerprinting web presence...")
        out.blank()

        with out.Timer() as t:
            with out.console.status("  [dim]analyzing...[/dim]", spinner="dots"):
                web = web_scan(target, timeout=6.0)

        if web.status == 0:
            out.tag("warn", "No HTTP response.")
        else:
            out.tag("info", f"Status [white]{web.status}[/white]  [dim]{web.url}[/dim]")
            if web.title:
                out.tag("info", f"Title  [white]{web.title[:72]}[/white]")
            out.blank()

            if web.tech:
                seen = set()
                for tech in web.tech:
                    if tech.name not in seen:
                        seen.add(tech.name)
                        out.tag("found", f"[white]{tech.name}[/white]  [dim]{tech.source}[/dim]")
                out.blank()

            if web.ssl:
                ssl = web.ssl
                if ssl.expired:
                    out.finding("CRIT", f"Certificate EXPIRED ({ssl.expires})")
                elif ssl.expiring_soon:
                    out.finding("HIGH", f"Certificate expires in {ssl.days_left} days ({ssl.expires})")

            crit_paths = [p for p in web.paths if p.severity in ("CRIT", "HIGH")]
            for p in crit_paths:
                out.finding(p.severity, p.path, f"HTTP {p.status}")

            for h in sorted(web.headers, key=lambda x: {"HIGH":0,"MED":1,"LOW":2}.get(x.severity,3)):
                out.finding(h.severity, h.header, h.desc)

            web_findings = len(crit_paths) + len(web.headers)
            web_crits = len([p for p in web.paths if p.severity == "CRIT"])
            out.summary(web_findings, "web findings", t.seconds, flagged=web_crits)

        results_data["web"] = {
            "url": web.url, "status": web.status, "title": web.title,
            "tech":    [asdict(t) for t in web.tech],
            "paths":   [asdict(p) for p in web.paths],
            "headers": [asdict(h) for h in web.headers],
            "ssl":     asdict(web.ssl) if web.ssl else {},
        }

    out.blank()

    # ── Auto-save to history ──────────────────────────────────────────────
    try:
        from viper.core import history as hist
        web_r = web if all_fangs and "web" in dir() else None
        _vulns = vulns_found if open_ports else []
        _missing = missing if open_ports else []
        scan_result = _build_scan_result(
            target=target, ip=ip, open_ports=open_ports,
            dns_result=dns_result, subs=subs,
            vulns_found=_vulns, missing=_missing,
            web_result=web_r, raw=results_data,
        )
        hist.save(scan_result)
        out.tag("info", f"History saved  [dim]{scan_result.summary()}[/dim]")
    except Exception:
        pass

    out.blank()

    # ── File export ───────────────────────────────────────────────────────
    if save:
        Path(save).write_text(
            json.dumps(results_data, indent=2, default=str), encoding="utf-8"
        )
        out.saved(save)

    if json_mode:
        jsonout.merge(results_data)
        jsonout.flush()

    out.set_silent(False)
    jsonout.disable()


def _build_scan_result(target: str, ip: str, open_ports, dns_result,
                       subs, vulns_found, missing, web_result=None,
                       duration: float = 0.0, raw: dict = None) -> "ScanResult":
    """Normalize all module outputs into a unified ScanResult."""
    from viper.core.models import (
        ScanResult, from_ports, from_subs, from_dns, from_vulns, from_web
    )
    findings = []
    findings += from_ports(open_ports, ip)
    findings += from_dns(dns_result, target)
    findings += from_subs(subs)
    if vulns_found is not None:
        findings += from_vulns(vulns_found, missing or [])
    if web_result:
        findings += from_web(web_result)

    return ScanResult(
        target=target, ip=ip, duration=duration,
        findings=findings, raw=raw or {},
    )
