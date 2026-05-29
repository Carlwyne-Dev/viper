"""
output/terminal.py — Viper's voice.
Aligned to the VIPER UI/UX Design System.

Primary: Venom Green
Support: Cyan (info), Yellow (warn), Red (critical), Green (success)
Never rainbow. Never loud. Precision predator.
"""

import time
from rich.console import Console
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn

# ── Design tokens ──────────────────────────────────────────────────────────────

VIPER_THEME = Theme({
    # Primary identity
    "venom":   "bold green",          # venom green — primary accent
    "venom_d": "green",               # venom dim — secondary
    "venom_x": "dim green",           # venom ghost

    # Semantic
    "info":    "cyan",
    "warn":    "yellow",
    "crit":    "bold red",
    "high":    "red",
    "med":     "yellow",
    "low":     "dim white",
    "ok":      "green",
    "success": "bold green",

    # Structure
    "label":   "bold white",
    "target":  "cyan",
    "port":    "bold green",
    "service": "white",
    "dim":     "dim white",
    "muted":   "dim",
    "flag":    "bold yellow",
})

console = Console(theme=VIPER_THEME, highlight=False)

SEVERITY_RANK = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}

SEVERITY_TAG = {
    "CRIT": "[crit][CRITICAL][/crit]",
    "HIGH": "[high][HIGH]   [/high]",
    "MED":  "[med][MEDIUM] [/med]",
    "LOW":  "[low][LOW]    [/low]",
    "INFO": "[dim][INFO]   [/dim]",
}

# Fang icons
ICON = {
    "info":    "◈",
    "success": "✓",
    "warn":    "▲",
    "crit":    "✕",
    "module":  "⟡",
    "active":  "▣",
    "open":    "✓",
    "found":   "✓",
    "miss":    "✕",
    "arrow":   "↳",
}

BANNER = """\
[venom]
 ██╗   ██╗██╗██████╗ ███████╗██████╗ 
 ██║   ██║██║██╔══██╗██╔════╝██╔══██╗
 ██║   ██║██║██████╔╝█████╗  ██████╔╝
 ╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
  ╚████╔╝ ██║██║     ███████╗██║  ██║
   ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝[/venom]
[dim]        we bite.[/dim]
"""


# ── Layout primitives ──────────────────────────────────────────────────────────

def banner():
    console.print(BANNER)
    console.print("  [venom_x][VIPER][/venom_x] [dim]Initializing...[/dim]\n")

def fang_header(name: str, icon: str = "⟡"):
    """Fang panel header — used for each module section."""
    console.print(f"\n[dim]╭{'─' * (len(name) + 4)}╮[/dim]")
    console.print(f"[dim]│[/dim] [venom]{icon} {name.upper()}[/venom] [dim]│[/dim]")
    console.print(f"[dim]╰{'─' * (len(name) + 4)}╯[/dim]")

def rule(label: str, target: str = ""):
    tgt = f"  [target]{target}[/target]" if target else ""
    console.print(f"\n[venom_x]──[/venom_x] [venom_d]{label}[/venom_d]{tgt} [dim]{'─' * max(1, 46 - len(label) - len(target))}[/dim]")

def blank():
    console.print()

def summary(found: int, label: str, elapsed: float, flagged: int = 0):
    flag_str = f"  [flag]▲ {flagged} flagged[/flag]" if flagged else ""
    console.print(f"\n  [dim]{found} {label}[/dim]{flag_str}  [dim]·  {elapsed:.1f}s[/dim]")

def tag(kind: str, message: str):
    """Generic bracketed tag line. [SCAN], [FOUND], [INFO], etc."""
    tags = {
        "scan":  "[venom_d][SCAN] [/venom_d]",
        "found": "[success][FOUND][/success]",
        "info":  "[info][INFO] [/info]",
        "warn":  "[warn][WARN] [/warn]",
        "error": "[crit][ERROR][/crit]",
        "tip":   "[dim][TIP]  [/dim]",
        "open":  "[success][OPEN] [/success]",
        "viper": "[venom_x][VIPER][/venom_x]",
    }
    t = tags.get(kind.lower(), f"[dim][{kind.upper()}][/dim]")
    console.print(f"  {t}  {message}")


# ── Data rendering ─────────────────────────────────────────────────────────────

def port_line(port: int, service: str, banner_text: str = "", flagged: bool = False):
    flag = "  [flag]▲[/flag]" if flagged else ""
    svc  = f"  [service]{service}[/service]" if service and service != "unknown" else ""
    bnr  = f"  [muted]{banner_text[:48]}[/muted]" if banner_text else ""
    console.print(f"  [success][OPEN][/success]  [port]{port:<6}[/port]{svc}{bnr}{flag}")

def ports_table(ports: list):
    """Aligned PORT / STATE / SERVICE table."""
    if not ports:
        return
    console.print(f"\n  [dim]{'PORT':<8}{'STATE':<8}SERVICE[/dim]")
    console.print(f"  [dim]{'─'*6}  {'─'*6}  {'─'*12}[/dim]")
    for p in ports:
        flag = "  [flag]▲[/flag]" if p.flagged else ""
        svc  = p.service or ""
        console.print(f"  [port]{p.port:<8}[/port][success]OPEN  [/success][service]{svc}[/service]{flag}")

def finding(severity: str, message: str, detail: str = ""):
    sev = SEVERITY_TAG.get(severity.upper(), f"[dim][{severity}][/dim]")
    detail_str = f"\n  [dim]         {detail}[/dim]" if detail else ""
    console.print(f"  {sev}  {message}{detail_str}")

def subdomain_line(fqdn: str, ip: str):
    console.print(f"  [venom_d]{ICON['arrow']}[/venom_d]  [target]{fqdn:<38}[/target]  [dim]{ip}[/dim]")

def dns_line(rtype: str, value: str):
    console.print(f"  [dim]{rtype:<8}[/dim][white]{value}[/white]")

def email_line(idx: int, email: str):
    console.print(f"  [dim]{idx:>2}.[/dim]  [target]{email}[/target]")

def social_hit(platform: str, url: str):
    console.print(f"  [success]{ICON['found']}[/success]  [label]{platform:<16}[/label]  [dim]{url}[/dim]")

def social_miss(platform: str):
    console.print(f"  [dim]{ICON['miss']}  {platform}[/dim]")

def cracked(word: str, hash_type: str, words_tried: int = 0):
    tried = f"  [dim]({words_tried:,} words tried)[/dim]" if words_tried else ""
    console.print(f"\n  [success][FOUND][/success]  [label]{word}[/label]  [dim]({hash_type})[/dim]{tried}")

def not_cracked(words_tried: int = 0, wordlist_src: str = ""):
    src = f"  [dim]({words_tried:,} words tried)[/dim]" if words_tried else ""
    console.print(f"\n  [dim][✕] Not found in wordlist.[/dim]{src}")
    if wordlist_src:
        console.print(f"  [dim]    source: {wordlist_src}[/dim]")
    tip("Tip: viper crack <hash> -w /usr/share/wordlists/rockyou.txt")

def hash_type(types: list):
    console.print(f"  [info][INFO] [/info]  [dim]type[/dim]  [label]{' / '.join(types)}[/label]")

def warn(msg: str):
    console.print(f"  [warn]{ICON['warn']}[/warn]  [dim]{msg}[/dim]")

def error(msg: str):
    console.print(f"  [crit]{ICON['crit']}[/crit]  [bold]{msg}[/bold]")

def tip(msg: str):
    console.print(f"  [dim][TIP]  {msg}[/dim]")

def saved(path: str):
    console.print(f"\n  [venom_d]{ICON['success']}[/venom_d]  [dim]saved →[/dim] [target]{path}[/target]")


# ── Progress ───────────────────────────────────────────────────────────────────

def scan_progress(total: int):
    return Progress(
        SpinnerColumn(style="green", spinner_name="dots"),
        TextColumn("  [dim]{task.description}[/dim]"),
        BarColumn(bar_width=36, style="dim green", complete_style="green"),
        TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )


# ── Timer ──────────────────────────────────────────────────────────────────────

class Timer:
    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_):
        self.elapsed = time.perf_counter() - self._start

    @property
    def seconds(self) -> float:
        return getattr(self, "elapsed", time.perf_counter() - self._start)


# ── Silent mode ────────────────────────────────────────────────────────────────
# Call set_silent(True) to suppress all output except findings and errors.

_silent = False

def set_silent(val: bool):
    global _silent
    _silent = val

def is_silent() -> bool:
    return _silent

# Wrap output functions for silent mode
_orig_rule    = rule
_orig_tag     = tag
_orig_summary = summary
_orig_blank   = blank

def rule(label: str, target: str = ""):
    if not _silent:
        _orig_rule(label, target)

def tag(kind: str, message: str):
    # Always show findings, errors, warns in silent mode
    if _silent and kind.lower() not in ("found", "error", "warn", "crit", "open"):
        return
    _orig_tag(kind, message)

def summary(found: int, label: str, elapsed: float, flagged: int = 0):
    if not _silent:
        _orig_summary(found, label, elapsed, flagged)

def blank():
    if not _silent:
        _orig_blank()


# ── Diff rendering ─────────────────────────────────────────────────────────────

def diff_header(target: str, prev_ts: str, curr_ts: str, delta: int):
    prev_d = prev_ts[:10]
    curr_d = curr_ts[:10]
    delta_str = (
        f"[crit]+{delta} risk[/crit]" if delta > 0
        else f"[success]{delta} risk[/success]" if delta < 0
        else "[dim]no change[/dim]"
    )
    console.print(f"\n  [dim]prev[/dim]  [white]{prev_d}[/white]")
    console.print(f"  [dim]curr[/dim]  [white]{curr_d}[/white]")
    console.print(f"  [dim]delta[/dim] {delta_str}")


def diff_new(f):
    sev = SEVERITY_TAG.get(f.severity, f.severity)
    console.print(f"  [success]+[/success] {sev}  [white]{f.title}[/white]  [dim]{f.description[:60]}[/dim]")


def diff_closed(f):
    sev = SEVERITY_TAG.get(f.severity, f.severity)
    console.print(f"  [dim]-[/dim] {sev}  [dim]{f.title}[/dim]")


def diff_changed(old, new):
    old_sev = SEVERITY_TAG.get(old.severity, old.severity)
    new_sev = SEVERITY_TAG.get(new.severity, new.severity)
    console.print(f"  [warn]~[/warn] {old_sev} [dim]→[/dim] {new_sev}  [white]{new.title}[/white]")


def diff_summary(new: int, closed: int, changed: int, stable: int):
    console.print(
        f"\n  [success]+{new} new[/success]"
        f"  [dim]-{closed} closed[/dim]"
        f"  [warn]~{changed} changed[/warn]"
        f"  [dim]{stable} stable[/dim]"
    )


def history_row(ts: str, n_findings: int, summary: dict):
    crits = summary.get("CRIT", 0)
    highs = summary.get("HIGH", 0)
    crit_str = f"  [crit]{crits}C[/crit]" if crits else ""
    high_str = f"  [high]{highs}H[/high]" if highs else ""
    console.print(
        f"  [dim]{ts[:16]}[/dim]"
        f"  [white]{n_findings:>3} findings[/white]"
        f"{crit_str}{high_str}"
    )


# ── OSINT deep rendering ───────────────────────────────────────────────────────

def osint_profile(p):
    """Render a single platform profile — found with metadata."""
    conf_color = "success" if p.confidence >= 85 else "warn" if p.confidence >= 60 else "dim"
    conf_str = f"[{conf_color}]{p.confidence}%[/{conf_color}]"

    console.print(f"\n  [venom]{p.platform}[/venom]  {conf_str}  [dim]{p.url}[/dim]")

    if p.name:
        console.print(f"  [dim]  name      [/dim][white]{p.name}[/white]")
    if p.bio:
        bio = p.bio[:80] + ("…" if len(p.bio) > 80 else "")
        console.print(f"  [dim]  bio       [/dim][white]{bio}[/white]")
    if p.joined:
        console.print(f"  [dim]  joined    [/dim][white]{p.joined}[/white]")
    if p.last_active:
        console.print(f"  [dim]  active    [/dim][white]{p.last_active}[/white]")
    if p.location:
        console.print(f"  [dim]  location  [/dim][white]{p.location}[/white]")
    if p.followers:
        console.print(f"  [dim]  followers [/dim][white]{p.followers:,}[/white]")
    if p.posts:
        console.print(f"  [dim]  posts     [/dim][white]{p.posts:,}[/white]")

    # Platform-specific extras
    if p.platform == "GitHub":
        langs = p.metadata.get("top_languages", [])
        if langs:
            console.print(f"  [dim]  languages [/dim][white]{', '.join(langs)}[/white]")
        top_repos = p.metadata.get("top_repos", [])
        if top_repos:
            repos_str = "  ".join(f"{r['name']}({r['stars']}★)" for r in top_repos[:3])
            console.print(f"  [dim]  top repos [/dim][white]{repos_str}[/white]")
        if p.metadata.get("twitter"):
            console.print(f"  [dim]  twitter   [/dim][dim]@{p.metadata['twitter']}[/dim]")

    if p.platform == "HackerNews":
        karma = p.metadata.get("karma", 0)
        subs  = p.metadata.get("submitted", 0)
        console.print(f"  [dim]  karma     [/dim][white]{karma:,}[/white]  [dim]·  {subs:,} submissions[/dim]")

    if p.platform == "Reddit":
        lk = p.metadata.get("link_karma", 0)
        ck = p.metadata.get("comment_karma", 0)
        console.print(f"  [dim]  karma     [/dim][white]{lk:,} link  ·  {ck:,} comment[/white]")

    if p.platform == "Dev.to":
        arts = p.metadata.get("articles", 0)
        if arts:
            console.print(f"  [dim]  articles  [/dim][white]{arts}[/white]")
        if p.metadata.get("github"):
            console.print(f"  [dim]  github    [/dim][dim]{p.metadata['github']}[/dim]")


def osint_miss(p):
    console.print(f"  [dim]✕  {p.platform:<16}  not found[/dim]")


def osint_verdict(confidence: int, verdict: str):
    conf_color = "crit" if confidence >= 80 else "warn" if confidence >= 50 else "dim"
    console.print(f"\n  [dim]confidence[/dim]  [{conf_color}]{confidence}%[/{conf_color}]")
    console.print(f"  [dim]verdict   [/dim]  [white]{verdict}[/white]")


def osint_signals(signals: list[str]):
    if not signals:
        return
    console.print(f"\n  [dim]signals:[/dim]")
    for s in signals:
        console.print(f"    [venom_x]◈[/venom_x]  [dim]{s}[/dim]")


def osint_tags(tags: list[str]):
    if not tags:
        return
    console.print(f"\n  [dim]interests:[/dim]  [white]{', '.join(tags)}[/white]")


def osint_activity(hint: str):
    if hint:
        console.print(f"  [dim]activity: [/dim]  [white]{hint}[/white]")
