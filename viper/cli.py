import click
from viper.output import terminal as out


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version="0.3.0", prog_name="viper")
def cli():
    """
    \b
    ██╗   ██╗██╗██████╗ ███████╗██████╗
    ██║   ██║██║██╔══██╗██╔════╝██╔══██╗
    ██║   ██║██║██████╔╝█████╗  ██████╔╝
    ╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
     ╚████╔╝ ██║██║     ███████╗██║  ██║
      ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
             we bite.  v0.3.0

    \b
    FANGS
      bite    target.com            scan + dns + subs + vuln
      bite    target.com --all      + web fingerprint (auto-saves history)
      venom   target.com            full assault → HTML + JSON report
      web     target.com            tech stack, paths, SSL, headers
      fang    target.com            port scan only
      recon   target.com            dns + subdomains
      osint   target --social       social media footprint
      osint   t --email F L domain  email pattern generation
      crack   <hash>                identify + wordlist crack
      report  scan.json -o out.html generate report
      config  --show                view / edit config

    \b
    INTELLIGENCE
      history target.com            show scan history
      diff    target.com            compare last two scans
      targets                       list all tracked targets

    \b
    EXAMPLES
      viper bite google.com
      viper bite google.com --all --save scan.json
      viper bite google.com --silent --json
      viper venom google.com --out ./reports
      viper web google.com
      viper fang 10.0.0.1 -p 1-65535 --threads 300
      viper recon google.com --whois --json
      viper crack 5f4dcc3b5aa765d61d8327deb882cf99
      viper crack <hash> -w /usr/share/wordlists/rockyou.txt
      viper config --set scan.threads 200
    """
    out.banner()


# ── viper bite ────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--all",    "all_fangs", is_flag=True, default=False, help="Include Web Fang in the flow.")
@click.option("--save",   "-s", default=None, metavar="FILE",  help="Save results as JSON file.")
@click.option("--silent", is_flag=True, default=False,          help="Suppress output except findings.")
@click.option("--json",   "json_mode", is_flag=True, default=False, help="Output results as JSON (for piping).")
def bite(target, all_fangs, save, silent, json_mode):
    """Fast recon — scan + DNS + subdomains + vuln hints.

    \b
    The default move. No flags needed.
    Auto-tunes scan timeout based on measured latency.
    --all adds Web Fang: tech stack, paths, SSL, headers.
    --json prints machine-readable JSON (suppresses terminal output).
    --silent suppresses all output except findings and errors.

    \b
    Examples:
      viper bite google.com
      viper bite google.com --all
      viper bite google.com --all --save scan.json
      viper bite google.com --silent --json | jq .ports
    """
    from viper.bite.quick import run
    run(target, save=save, silent=silent, all_fangs=all_fangs, json_mode=json_mode)


# ── viper venom ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--out", "-o", "output_dir", default=".", metavar="DIR", help="Output directory for reports.")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output results as JSON.")
def venom(target, output_dir, json_mode):
    """Full assault — everything, auto-saved as HTML + JSON report.

    \b
    Runs: PORT FANG (all 65535) → DNS FANG → VENOM FANG → WEB FANG
    Auto-tunes scan timeout. Saves HTML report + JSON data.

    \b
    Examples:
      viper venom google.com
      viper venom google.com --out ./reports
      viper venom google.com --json
    """
    from viper.bite.deep import run
    run(target, output_dir=output_dir, json_mode=json_mode)


# ── viper web ─────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--timeout", "-t", default=6.0, show_default=True, help="Request timeout (s).")
@click.option("--no-paths", is_flag=True, default=False, help="Skip sensitive path checks.")
@click.option("--no-ssl",   is_flag=True, default=False, help="Skip SSL analysis.")
@click.option("--save",  "-s", default=None, metavar="FILE", help="Save results as JSON.")
@click.option("--json",  "json_mode", is_flag=True, default=False, help="Output as JSON.")
def web(target, timeout, no_paths, no_ssl, save, json_mode):
    """Web Fang — tech fingerprint, sensitive paths, SSL, security headers.

    \b
    Detects: server, CMS, frameworks, languages, CDN.
    Checks:  30+ sensitive paths (.env, .git, admin panels, backups, APIs).
    Audits:  SSL cert expiry, TLS version, 6 security headers.

    \b
    Examples:
      viper web google.com
      viper web google.com --save web.json
      viper web google.com --no-paths
      viper web google.com --json | jq .tech
    """
    import json as jsonlib
    from dataclasses import asdict
    from pathlib import Path
    from viper.modules.web import scan as web_scan
    from viper.core import jsonout

    if json_mode:
        jsonout.enable()
        out.set_silent(True)

    out.rule("WEB FANG", target)
    out.tag("viper", f"Analyzing → [cyan]{target}[/cyan]")
    out.blank()

    with out.Timer() as t:
        with out.console.status("  [dim]fingerprinting...[/dim]", spinner="dots"):
            result = web_scan(target, timeout=timeout,
                              check_paths=not no_paths, check_ssl=not no_ssl)

    if result.status == 0:
        out.error(f"No response from {target}")
        return

    out.tag("info", f"Status [white]{result.status}[/white]  [dim]{result.url}[/dim]")
    if result.redirects_to and result.redirects_to != result.url:
        out.tag("info", f"Redirects → [dim]{result.redirects_to}[/dim]")
    if result.title:
        out.tag("info", f"Title  [white]{result.title[:72]}[/white]")
    out.blank()

    if result.tech:
        out.rule("TECH STACK")
        out.blank()
        seen = set()
        for tech in result.tech:
            if tech.name not in seen:
                seen.add(tech.name)
                out.tag("found", f"[white]{tech.name}[/white]  [dim]{tech.source}[/dim]")
        out.blank()

    if result.ssl:
        ssl = result.ssl
        out.rule("SSL / TLS")
        out.blank()
        if ssl.valid:
            out.tag("info", f"Issuer  [white]{ssl.issuer}[/white]")
            out.tag("info", f"TLS     [white]{ssl.tls_version}[/white]")
            if ssl.expired:
                out.finding("CRIT", f"Certificate EXPIRED  ({ssl.expires})")
            elif ssl.expiring_soon:
                out.finding("HIGH", f"Expires in {ssl.days_left} days  ({ssl.expires})")
            else:
                out.tag("info", f"Expires [white]{ssl.expires}[/white]  [dim]({ssl.days_left} days)[/dim]")
        else:
            out.finding("HIGH", "SSL certificate invalid or untrusted")
        out.blank()

    if result.paths:
        out.rule("PATHS")
        out.blank()
        for p in [x for x in result.paths if x.severity != "INFO"]:
            out.finding(p.severity, p.path, f"HTTP {p.status}")
        for p in [x for x in result.paths if x.severity == "INFO"]:
            out.tag("found", f"[dim]{p.path}[/dim]  [dim]HTTP {p.status}[/dim]")
        if result.robots_txt:
            out.blank()
            out.tag("info", f"robots.txt  [dim]{result.robots_txt[:80]}[/dim]")
        out.blank()

    if result.headers:
        out.rule("SECURITY HEADERS")
        out.blank()
        for h in sorted(result.headers, key=lambda x: {"HIGH":0,"MED":1,"LOW":2}.get(x.severity,3)):
            out.finding(h.severity, h.header, h.desc)
        out.blank()

    crits = len([p for p in result.paths if p.severity == "CRIT"])
    total = len([p for p in result.paths if p.severity not in ("INFO","LOW")]) + len(result.headers)
    out.summary(total, "findings", t.seconds, flagged=crits)
    out.blank()

    result_data = {
        "target": target, "url": result.url, "status": result.status,
        "title":   result.title,
        "tech":    [asdict(t) for t in result.tech],
        "paths":   [asdict(p) for p in result.paths],
        "headers": [asdict(h) for h in result.headers],
        "ssl":     asdict(result.ssl) if result.ssl else {},
    }

    if save:
        Path(save).write_text(jsonlib.dumps(result_data, indent=2, default=str), encoding="utf-8")
        out.saved(save)

    if json_mode:
        jsonout.merge(result_data)
        jsonout.flush()

    out.set_silent(False)
    jsonout.disable()


# ── viper fang ────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--ports",   "-p", default=None,  metavar="RANGE",    help="Port range. Default: from config.")
@click.option("--timeout", "-t", default=None,  type=float,          help="Timeout per port. Default: auto.")
@click.option("--threads",       default=None,  type=int,            help="Thread count. Default: from config.")
@click.option("--save",    "-s", default=None,  metavar="FILE",      help="Save results as JSON.")
@click.option("--silent",        is_flag=True,  default=False,       help="No output except results.")
@click.option("--json",   "json_mode", is_flag=True, default=False,  help="Output as JSON.")
def fang(target, ports, timeout, threads, save, silent, json_mode):
    """Focused port scan — fast, precise, configurable.

    \b
    Auto-tunes timeout based on target latency unless --timeout is set.

    \b
    Examples:
      viper fang 10.0.0.1
      viper fang 10.0.0.1 -p 1-65535
      viper fang 10.0.0.1 -p 22,80,443,3306 --threads 200
      viper fang 10.0.0.1 --json | jq .ports
    """
    import json as jsonlib
    from viper.core import errors, jsonout
    from viper.core.config import load as cfg
    from viper.core.latency import tune_timeout
    from viper.modules.scanner import scan, parse_ports
    from pathlib import Path

    if json_mode:
        jsonout.enable()
        out.set_silent(True)

    c = cfg().scan
    port_str  = ports or c.ports
    port_list = parse_ports(port_str)

    out.rule("PORT FANG", target)
    out.tag("scan", f"[dim]{port_str}[/dim] — [dim]{len(port_list)} ports[/dim]")
    out.blank()

    try:
        ip = errors.resolve(target)
    except errors.ResolveError as e:
        errors.handle(e); return

    auto_timeout = timeout or tune_timeout(ip)
    if not timeout:
        out.tag("info", f"Timeout auto-tuned → [white]{auto_timeout:.2f}s[/white]")
        out.blank()

    with out.Timer() as t:
        if not silent and not json_mode:
            with out.scan_progress(len(port_list)) as progress:
                task = progress.add_task("scanning", total=len(port_list))
                results = scan(ip, port_str, auto_timeout, threads or c.threads,
                               on_progress=lambda: progress.advance(task))
        else:
            results = scan(ip, port_str, auto_timeout, threads or c.threads)

    out.ports_table(results)
    flagged = sum(1 for p in results if p.flagged)
    out.summary(len(results), "open ports", t.seconds, flagged)
    out.blank()

    data = {"target": target, "ip": ip,
            "ports": [{"port": p.port, "service": p.service, "flagged": p.flagged} for p in results]}

    if save:
        Path(save).write_text(jsonlib.dumps(data, indent=2), encoding="utf-8")
        out.saved(save)

    if json_mode:
        jsonout.merge(data)
        jsonout.flush()

    out.set_silent(False)
    jsonout.disable()


# ── viper recon ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--whois", is_flag=True, default=False, help="Include WHOIS lookup.")
@click.option("--save",  "-s", default=None, metavar="FILE", help="Save as JSON.")
@click.option("--json",  "json_mode", is_flag=True, default=False, help="Output as JSON.")
def recon(target, whois, save, json_mode):
    """DNS records + concurrent subdomain enumeration.

    \b
    Examples:
      viper recon google.com
      viper recon google.com --whois
      viper recon google.com --save recon.json
      viper recon google.com --json | jq .subs
    """
    import json as jsonlib
    from dataclasses import asdict
    from pathlib import Path
    from viper.modules import recon as r
    from viper.core import jsonout

    if json_mode:
        jsonout.enable()
        out.set_silent(True)

    out.rule("DNS FANG", target)
    out.tag("scan", "Resolving DNS records...")
    out.blank()

    with out.Timer() as t:
        dns = r.dns(target)

    for rtype in ("A", "AAAA", "MX", "NS", "TXT"):
        for val in getattr(dns, rtype, []):
            if not json_mode:
                out.dns_line(rtype, val)

    total = sum(len(getattr(dns, rtype, [])) for rtype in ("A","AAAA","MX","NS","TXT"))
    out.summary(total, "records", t.seconds)

    w = {}
    if whois:
        out.blank()
        out.rule("WHOIS", target)
        with out.Timer() as t:
            w = r.whois(target)
        for k, v in w.items():
            if v and not json_mode:
                out.dns_line(k, str(v)[:60])
        out.summary(len(w), "fields", t.seconds)

    out.blank()
    out.rule("DNS FANG", f"subdomains · {target}")
    out.tag("scan", "Enumerating subdomains (concurrent)...")
    out.blank()

    with out.Timer() as t:
        subs = r.subdomains(target, threads=50)

    for s in subs:
        out.tag("found", f"[target]{s.subdomain}[/target]  [dim]{s.ip}[/dim]")
    if not subs:
        out.tag("info", "No subdomains resolved.")
    out.summary(len(subs), "subdomains", t.seconds)
    out.blank()

    data = {"target": target, "dns": asdict(dns),
            "subs": [asdict(s) for s in subs], "whois": w}

    if save:
        Path(save).write_text(jsonlib.dumps(data, indent=2, default=str), encoding="utf-8")
        out.saved(save)

    if json_mode:
        jsonout.merge(data)
        jsonout.flush()

    out.set_silent(False)
    jsonout.disable()


# ── viper osint ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--email",  "-e", nargs=3, metavar="FIRST LAST DOMAIN", help="Generate email patterns.")
@click.option("--social", "-s", is_flag=True, default=False,           help="Check social platforms.")
@click.option("--json",   "json_mode", is_flag=True, default=False,    help="Output as JSON.")
def osint(target, email, social, json_mode):
    """OSINT — email pattern generation + social media footprint.

    \b
    Examples:
      viper osint johndoe --social
      viper osint t --email john doe company.com
      viper osint johndoe --social --json | jq .social
    """
    import json as jsonlib
    from viper.modules.osint import email_guesses, social as check_social
    from viper.core import jsonout

    if json_mode:
        jsonout.enable()
        out.set_silent(True)

    out.rule("SHADOW FANG", target)
    out.blank()

    data = {"target": target}

    if email:
        first, last, domain = email
        out.tag("scan", f"Email patterns for [cyan]{first} {last}@{domain}[/cyan]")
        out.blank()
        guesses = email_guesses(first, last, domain)
        for i, e in enumerate(guesses, 1):
            out.email_line(i, e)
        out.blank()
        data["emails"] = guesses

    if social:
        out.tag("scan", f"Checking platforms for [cyan]{target}[/cyan]")
        out.blank()
        with out.Timer() as t:
            with out.console.status("  [dim]checking...[/dim]", spinner="dots"):
                results = check_social(target)
        hits = [r for r in results if r.found]
        for r in [x for x in results if x.found]:
            out.social_hit(r.platform, r.url)
        out.blank()
        for r in [x for x in results if not x.found]:
            out.social_miss(r.platform)
        out.summary(len(hits), "profiles found", t.seconds)
        out.blank()
        data["social"] = [{"platform": r.platform, "url": r.url, "found": r.found} for r in results]

    if not email and not social:
        out.warn("Specify --email FIRST LAST DOMAIN or --social")

    if json_mode:
        jsonout.merge(data)
        jsonout.flush()

    out.set_silent(False)
    jsonout.disable()


# ── viper crack ───────────────────────────────────────────────────────────────

@cli.command()
@click.argument("hash_input")
@click.option("--wordlist", "-w", default=None, metavar="FILE", help="Wordlist path.")
@click.option("--identify", "-i", is_flag=True, default=False,  help="Identify only, don't crack.")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output as JSON.")
def crack(hash_input, wordlist, identify, json_mode):
    """Identify hash type and crack with a wordlist.

    \b
    Supports: MD5, SHA1, SHA256, SHA384, SHA512.
    Built-in wordlist included. Supply rockyou.txt for real cracking.

    \b
    Examples:
      viper crack 5f4dcc3b5aa765d61d8327deb882cf99
      viper crack <hash> -w /usr/share/wordlists/rockyou.txt
      viper crack <hash> --identify
      viper crack <hash> --json
    """
    from viper.modules.crack import crack as do_crack, identify as do_id
    from viper.core import jsonout

    if json_mode:
        jsonout.enable()
        out.set_silent(True)

    out.rule("VENOM FANG", "hash")
    out.blank()

    if identify:
        types = do_id(hash_input)
        out.hash_type(types)
        out.blank()
        if json_mode:
            jsonout.merge({"hash": hash_input, "types": types})
            jsonout.flush()
        return

    out.tag("scan", "Identifying and cracking...")
    out.blank()

    with out.Timer() as t:
        with out.console.status("  [dim]cracking...[/dim]", spinner="dots"):
            result = do_crack(hash_input, wordlist_path=wordlist)

    out.tag("info", f"Wordlist  [dim]{result.wordlist_src}[/dim]")
    out.blank()
    out.hash_type(result.hash_types)
    if result.cracked:
        out.cracked(result.cracked, result.algo_used or "", result.words_tried)
    else:
        out.not_cracked(result.words_tried, result.wordlist_src)
    out.blank()

    if json_mode:
        jsonout.merge({"hash": hash_input, "types": result.hash_types,
                       "cracked": result.cracked, "algo": result.algo_used})
        jsonout.flush()

    out.set_silent(False)
    jsonout.disable()


# ── viper report ──────────────────────────────────────────────────────────────

@cli.command()
@click.argument("json_file")
@click.option("--output", "-o", default="viper-report.html", show_default=True, help="Output file path.")
@click.option("--format", "-f", "fmt", type=click.Choice(["html", "json"]), default="html", help="Report format.")
def report(json_file, output, fmt):
    """Generate a report from any saved scan JSON file.

    \b
    Examples:
      viper bite google.com --save scan.json
      viper report scan.json -o report.html
      viper report scan.json -o data.json --format json
    """
    import json as jsonlib
    from viper.output.report import render_html, render_json

    out.rule("EXPORT")
    out.blank()
    try:
        data = jsonlib.loads(open(json_file, encoding="utf-8").read())
        if fmt == "html":
            render_html(data, output)
        else:
            render_json(data, output)
        out.saved(output)
    except FileNotFoundError:
        out.error(f"File not found: {json_file}")
        out.tip("Run viper bite target --save scan.json first")
    except Exception as e:
        out.error(str(e))
    out.blank()


# ── viper config ──────────────────────────────────────────────────────────────

@cli.command("config")
@click.option("--show", is_flag=True,          help="Show current config.")
@click.option("--init", is_flag=True,          help="Create default config file.")
@click.option("--set",  "kv", nargs=2, multiple=True, metavar="KEY VALUE", help="Set a config value.")
def config_cmd(show, init, kv):
    """View and edit Viper config (~/.viper/config.json).

    \b
    Config controls scan threads, timeout, port range, and output defaults.

    \b
    Examples:
      viper config --show
      viper config --init
      viper config --set scan.threads 200
      viper config --set scan.timeout 0.3
      viper config --set scan.ports 1-65535
    """
    from viper.core.config import load, save, init as do_init, ViperConfig, ScanConfig, ReconConfig, OutputConfig
    from dataclasses import asdict

    out.rule("CONFIG")
    out.blank()

    if init:
        do_init()
        out.tag("info", "Config initialized → [dim]~/.viper/config.json[/dim]")

    if kv:
        cfg = load()
        d = asdict(cfg)
        for key_path, value in kv:
            parts = key_path.split(".")
            if len(parts) == 2:
                section, key = parts
                if section in d and key in d[section]:
                    v = d[section][key]
                    try:
                        if isinstance(v, bool):    d[section][key] = value.lower() == "true"
                        elif isinstance(v, int):   d[section][key] = int(value)
                        elif isinstance(v, float): d[section][key] = float(value)
                        else:                      d[section][key] = value
                        out.tag("info", f"[dim]{key_path}[/dim] → [white]{d[section][key]}[/white]")
                    except ValueError:
                        out.error(f"Invalid value for {key_path}: {value}")
        new_cfg = ViperConfig()
        new_cfg.scan   = ScanConfig(**d["scan"])
        new_cfg.recon  = ReconConfig(**d["recon"])
        new_cfg.output = OutputConfig(**d["output"])
        save(new_cfg)
        out.blank()
        out.tag("info", "Saved.")

    if show or not any([init, kv]):
        cfg = load()
        for section, values in asdict(cfg).items():
            out.blank()
            out.console.print(f"  [venom]⟡ {section.upper()}[/venom]")
            for k, v in values.items():
                out.console.print(f"    [dim]{k:<18}[/dim][white]{v}[/white]")
        out.blank()


if __name__ == "__main__":
    cli()


# ── viper history ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--limit", "-n", default=10, show_default=True, help="Number of scans to show.")
def history(target, limit):
    """Show scan history for a target.

    \b
    Examples:
      viper history google.com
      viper history google.com -n 5
    """
    from viper.core import history as hist

    out.rule("HISTORY", target)
    out.blank()

    files = hist.scans_for(target)
    if not files:
        out.tag("info", f"No scan history for [cyan]{target}[/cyan]")
        out.tip("Run: viper bite " + target)
        out.blank()
        return

    out.tag("info", f"[white]{len(files)}[/white] scans on record")
    out.blank()

    for f in files[:limit]:
        try:
            result = hist.load(f)
            out.history_row(result.timestamp, len(result.findings), result.summary())
        except Exception:
            out.console.print(f"  [dim]{f.name}[/dim]  [dim]unreadable[/dim]")

    if len(files) > limit:
        out.blank()
        out.tip(f"{len(files) - limit} more scans. Use -n {len(files)} to see all.")
    out.blank()


# ── viper diff ────────────────────────────────────────────────────────────────

@cli.command()
@click.argument("target")
@click.option("--json", "json_mode", is_flag=True, default=False, help="Output diff as JSON.")
def diff(target, json_mode):
    """Compare the two most recent scans for a target.

    \b
    Shows: new findings, closed findings, changed severity, risk delta.
    Requires at least 2 scans in history.

    \b
    Examples:
      viper diff google.com
      viper diff google.com --json
    """
    import json as jsonlib
    from viper.core import history as hist
    from viper.core.diff import compare
    from viper.core import jsonout as jo

    if json_mode:
        jo.enable()
        out.set_silent(True)

    out.rule("DIFF", target)
    out.blank()

    prev = hist.previous(target)
    curr = hist.latest(target)

    if not curr:
        out.error(f"No scan history for {target}")
        out.tip(f"Run: viper bite {target}  (twice to enable diff)")
        out.blank()
        return

    if not prev:
        out.tag("info", "Only one scan on record — need two to diff.")
        out.tip(f"Run viper bite {target} again later to compare.")
        out.blank()
        return

    result = compare(prev, curr)
    out.diff_header(target, result.previous, result.current, result.risk_delta())
    out.blank()

    if not result.has_changes:
        out.tag("info", "No changes detected between scans.")
        out.diff_summary(0, 0, 0, len(result.stable))
        out.blank()
        return

    if result.new:
        out.rule("NEW FINDINGS")
        out.blank()
        for f in result.new:
            out.diff_new(f)
        out.blank()

    if result.closed:
        out.rule("CLOSED")
        out.blank()
        for f in result.closed:
            out.diff_closed(f)
        out.blank()

    if result.changed:
        out.rule("CHANGED")
        out.blank()
        for old, new in result.changed:
            out.diff_changed(old, new)
        out.blank()

    out.diff_summary(
        len(result.new), len(result.closed),
        len(result.changed), len(result.stable)
    )
    out.blank()

    if json_mode:
        jo.merge({
            "target": target,
            "previous": result.previous,
            "current":  result.current,
            "risk_delta": result.risk_delta(),
            "new":     [f.to_dict() for f in result.new],
            "closed":  [f.to_dict() for f in result.closed],
            "changed": [{"old": o.to_dict(), "new": n.to_dict()} for o, n in result.changed],
        })
        jo.flush()

    out.set_silent(False)
    jo.disable()


# ── viper targets ─────────────────────────────────────────────────────────────

@cli.command()
def targets():
    """List all targets with scan history.

    \b
    Example:
      viper targets
    """
    from viper.core import history as hist

    out.rule("TARGETS")
    out.blank()

    all_t = hist.all_targets()
    if not all_t:
        out.tag("info", "No scan history yet.")
        out.tip("Run: viper bite <target>")
        out.blank()
        return

    for t in sorted(all_t):
        count = hist.scan_count(t)
        latest = hist.latest(t)
        ts = latest.timestamp[:10] if latest else "unknown"
        out.console.print(
            f"  [target]{t:<30}[/target]"
            f"  [dim]{count} scan{'s' if count != 1 else ''}[/dim]"
            f"  [dim]last: {ts}[/dim]"
        )

    out.blank()
    out.summary(len(all_t), "targets on record", 0.0)
    out.blank()
