"""
viper/tui/app.py — Viper TUI Dashboard.

Built with Textual. Scans run in background workers.
Findings stream in live. History browsable. Diffs on demand.

Run: viper tui
"""

from __future__ import annotations
import threading
from datetime import datetime
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.reactive import reactive
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import (
    Button, Footer, Header, Input, Label,
    ListItem, ListView, ProgressBar, RichLog, Static, TabbedContent, TabPane,
)
from textual.css.query import NoMatches


# ── CSS ────────────────────────────────────────────────────────────────────────

CSS = """
/* Base */
Screen {
    background: #080808;
    color: #cccccc;
}

/* Banner */
#banner {
    color: #22c55e;
    text-align: center;
    padding: 0 1;
    height: 9;
}

/* Layout */
#layout {
    height: 1fr;
}

#sidebar {
    width: 18;
    background: #0e0e0e;
    border-right: solid #1a1a1a;
    padding: 1 1;
}

#main {
    width: 1fr;
    padding: 0 1;
}

/* Sidebar nav items */
.nav-label {
    color: #555;
    margin-top: 1;
    margin-bottom: 0;
    text-style: bold;
}

.nav-item {
    background: transparent;
    color: #888;
    border: none;
    padding: 0 1;
    height: 1;
    min-width: 1;
    width: 1fr;
}

.nav-item:hover {
    color: #22c55e;
    background: #111;
}

.nav-item.active {
    color: #22c55e;
    background: #0d1f0d;
    border-left: solid #22c55e;
}

/* Target input row */
#target-row {
    height: 3;
    margin-bottom: 1;
}

#target-input {
    width: 1fr;
    background: #0e0e0e;
    border: solid #2a2a2a;
    color: #f0f0f0;
}

#target-input:focus {
    border: solid #22c55e;
}

#btn-bite {
    width: 10;
    background: #14532d;
    color: #22c55e;
    border: solid #22c55e;
    margin-left: 1;
}

#btn-bite:hover {
    background: #22c55e;
    color: #080808;
}

#btn-stop {
    width: 10;
    background: #3f0000;
    color: #ef4444;
    border: solid #ef4444;
    margin-left: 1;
    display: none;
}

#btn-stop.visible {
    display: block;
}

#btn-export {
    width: 10;
    background: #1a1a1a;
    color: #555;
    border: solid #2a2a2a;
    margin-left: 1;
}

#btn-export:hover {
    color: #22c55e;
    border: solid #22c55e;
}

#scan-progress {
    height: 1;
    margin-bottom: 1;
}

ProgressBar > .bar--bar {
    color: #22c55e;
}

ProgressBar > .bar--complete {
    color: #22c55e;
}

/* Scan log */
#scan-log {
    height: 1fr;
    background: #080808;
    border: solid #1a1a1a;
    scrollbar-color: #22c55e #0e0e0e;
    padding: 0 1;
}

/* Findings panel */
#findings-panel {
    height: 1fr;
    background: #080808;
    border: solid #1a1a1a;
    scrollbar-color: #22c55e #0e0e0e;
    padding: 0 1;
}

.finding-crit {
    color: #ef4444;
    text-style: bold;
}
.finding-high {
    color: #f97316;
}
.finding-med {
    color: #eab308;
}
.finding-low {
    color: #555;
}
.finding-info {
    color: #444;
}

/* History list */
#history-list {
    height: 1fr;
    background: #080808;
    border: solid #1a1a1a;
}

.history-item {
    color: #888;
    padding: 0 1;
}

.history-item:hover {
    color: #22c55e;
    background: #0d1f0d;
}

/* Diff panel */
#diff-content {
    height: 1fr;
    background: #080808;
    border: solid #1a1a1a;
    padding: 0 1;
    overflow-y: auto;
}

/* Section headers */
.section-header {
    color: #22c55e;
    text-style: bold;
    margin-top: 1;
    margin-bottom: 0;
    border-bottom: solid #1a1a1a;
}

/* Status bar */
#status-bar {
    height: 1;
    background: #0e0e0e;
    color: #555;
    padding: 0 1;
}

.status-target {
    color: #06b6d4;
}

.status-findings {
    color: #22c55e;
}

/* CVE search */
#cve-row {
    height: 3;
    margin-bottom: 1;
}

#cve-input {
    width: 1fr;
    background: #0e0e0e;
    border: solid #2a2a2a;
    color: #f0f0f0;
}

#cve-input:focus {
    border: solid #22c55e;
}

#diff-input {
    width: 1fr;
    background: #0e0e0e;
    border: solid #2a2a2a;
    color: #f0f0f0;
}

#diff-input:focus {
    border: solid #22c55e;
}

#btn-diff {
    width: 10;
    background: #14532d;
    color: #22c55e;
    border: solid #22c55e;
    margin-left: 1;
}

#btn-diff:hover {
    background: #22c55e;
    color: #080808;
}

#btn-diff-targets {
    width: 12;
    background: #1a1a1a;
    color: #555;
    border: solid #2a2a2a;
    margin-left: 1;
}

#btn-diff-targets:hover {
    color: #22c55e;
    border: solid #22c55e;
}

#diff-hint {
    color: #555;
    height: 1;
    padding: 0 1;
}

#btn-cve-search {
    width: 12;
    background: #14532d;
    color: #22c55e;
    border: solid #22c55e;
    margin-left: 1;
}

#cve-results {
    height: 1fr;
    background: #080808;
    border: solid #1a1a1a;
    padding: 0 1;
    overflow-y: auto;
}

/* Crack */
#crack-row {
    height: 3;
    margin-bottom: 1;
}

#crack-input {
    width: 1fr;
    background: #0e0e0e;
    border: solid #2a2a2a;
    color: #f0f0f0;
}

#crack-input:focus {
    border: solid #22c55e;
}

#btn-crack-paste {
    width: 10;
    background: #1a1a1a;
    color: #555;
    border: solid #2a2a2a;
    margin-left: 1;
}

#btn-crack-paste:hover {
    color: #22c55e;
    border: solid #22c55e;
}

#btn-crack {
    width: 12;
    background: #14532d;
    color: #22c55e;
    border: solid #22c55e;
    margin-left: 1;
}

#crack-output {
    height: 1fr;
    background: #080808;
    border: solid #1a1a1a;
    padding: 0 1;
    overflow-y: auto;
}
"""

BANNER = """\
 ██╗   ██╗██╗██████╗ ███████╗██████╗
 ██║   ██║██║██╔══██╗██╔════╝██╔══██╗
 ██║   ██║██║██████╔╝█████╗  ██████╔╝
 ╚██╗ ██╔╝██║██╔═══╝ ██╔══╝  ██╔══██╗
  ╚████╔╝ ██║██║     ███████╗██║  ██║
   ╚═══╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝  we bite."""


SEV_STYLE = {
    "CRIT": "finding-crit",
    "HIGH": "finding-high",
    "MED":  "finding-med",
    "LOW":  "finding-low",
    "INFO": "finding-info",
}


# ── Main App ───────────────────────────────────────────────────────────────────

class ViperTUI(App):
    CSS = CSS
    TITLE = "VIPER"

    BINDINGS = [
        Binding("q",          "quit",             "Quit"),
        Binding("1",          "tab_scan",         "Scan"),
        Binding("2",          "tab_history",      "History"),
        Binding("3",          "tab_diff",         "Diff"),
        Binding("4",          "tab_cve",          "CVE"),
        Binding("5",          "tab_crack",        "Crack"),
        Binding("6",          "tab_targets",      "Targets"),
        Binding("ctrl+v",     "paste_clipboard",  "Paste", show=False),
        Binding("shift+ins",  "paste_clipboard",  "Paste", show=False),
        Binding("ctrl+c",     "quit",             "Quit",  show=False),
    ]

    current_target: reactive[str] = reactive("")
    finding_count:  reactive[int] = reactive(0)
    scan_running:   reactive[bool] = reactive(False)
    current_tab:    reactive[str] = reactive("scan")
    current_mode:   reactive[str] = reactive("bite")  # bite | venom | web
    _stop_flag: bool = False
    _history_files: list = []   # ordered list of (target, path) matching history-list
    _target_names:  list = []   # ordered list of target names matching targets-list

    def compose(self) -> ComposeResult:
        yield Static(BANNER, id="banner")
        with Horizontal(id="layout"):
            # Sidebar
            with Vertical(id="sidebar"):
                yield Label("-- FANGS --", classes="nav-label")
                yield Button(">  Bite",    id="nav-bite",    classes="nav-item active")
                yield Button(">  Venom",   id="nav-venom",   classes="nav-item")
                yield Button(">  Web",     id="nav-web",     classes="nav-item")
                yield Label("-- TOOLS --", classes="nav-label")
                yield Button("*  CVE",     id="nav-cve",     classes="nav-item")
                yield Button("*  Crack",   id="nav-crack",   classes="nav-item")
                yield Label("-- DATA --",  classes="nav-label")
                yield Button("-  History", id="nav-history", classes="nav-item")
                yield Button("-  Diff",    id="nav-diff",    classes="nav-item")
                yield Button("-  Targets", id="nav-targets", classes="nav-item")

            # Main panel
            with Vertical(id="main"):
                with TabbedContent(id="tabs", initial="scan"):
                    # ── Scan tab
                    with TabPane("Scan", id="scan"):
                        with Horizontal(id="target-row"):
                            yield Input(
                                placeholder="target.com or IP...",
                                id="target-input",
                            )
                            yield Button("BITE",   id="btn-bite")
                            yield Button("STOP",   id="btn-stop")
                            yield Button("EXPORT", id="btn-export")
                        yield ProgressBar(id="scan-progress", total=100, show_eta=False)
                        with Horizontal():
                            with Vertical(id="log-col"):
                                yield Label("── OUTPUT ──", classes="section-header")
                                yield RichLog(id="scan-log", highlight=False, markup=True)
                            with Vertical(id="findings-col"):
                                yield Label("── FINDINGS ──", classes="section-header")
                                yield ScrollableContainer(
                                    id="findings-panel"
                                )

                    # ── History tab
                    with TabPane("History", id="history"):
                        yield Label("── RECENT SCANS ──", classes="section-header")
                        yield ListView(id="history-list")
                        yield Static("", id="history-detail")

                    # ── Targets tab
                    with TabPane("Targets", id="targets"):
                        yield Label("── TRACKED TARGETS ──", classes="section-header")
                        yield ListView(id="targets-list")

                    # ── Diff tab
                    with TabPane("Diff", id="diff"):
                        with Horizontal(id="diff-row"):
                            yield Input(
                                placeholder="target.com (must have 2+ scans)...",
                                id="diff-input",
                            )
                            yield Button("DIFF", id="btn-diff")
                            yield Button("TARGETS", id="btn-diff-targets")
                        yield Static("", id="diff-hint")
                        yield Label("── CHANGES ──", classes="section-header")
                        yield ScrollableContainer(id="diff-content")

                    # ── CVE tab
                    with TabPane("CVE", id="cve"):
                        with Horizontal(id="cve-row"):
                            yield Input(
                                placeholder="nginx, apache 2.4, CVE-2021-41773...",
                                id="cve-input",
                            )
                            yield Button("SEARCH", id="btn-cve-search")
                        yield Label("── RESULTS ──", classes="section-header")
                        yield ScrollableContainer(id="cve-results")

                    # ── Crack tab
                    with TabPane("Crack", id="crack"):
                        with Horizontal(id="crack-row"):
                            yield Input(
                                placeholder="type or paste hash here...",
                                id="crack-input",
                            )
                            yield Button("PASTE", id="btn-crack-paste")
                            yield Button("CRACK", id="btn-crack")
                        yield Label("── OUTPUT ──", classes="section-header")
                        yield ScrollableContainer(id="crack-output")

        yield Static(id="status-bar")

    def on_mount(self) -> None:
        self._update_status()
        self._load_history()

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        lv_id = event.list_view.id
        idx   = event.list_view.index
        if lv_id == "history-list":
            self._drill_history(idx)
        elif lv_id == "targets-list":
            self._drill_target(idx)

    def _safe_call(self, fn):
        """Call fn on the main thread safely — from any thread."""
        if threading.get_ident() == self._thread_id:
            fn()
        else:
            self.call_from_thread(fn)

    def _set_mode(self, mode: str):
        """Switch active fang mode, clear panels, update UI."""
        self.current_mode = mode
        self.action_tab_scan()

        # Clear output log
        try:
            self.query_one("#scan-log", RichLog).clear()
        except Exception:
            pass

        # Clear findings panel
        try:
            self.query_one("#findings-panel", ScrollableContainer).remove_children()
            self.finding_count = 0
        except Exception:
            pass

        # Reset progress bar to 0
        try:
            self.query_one("#scan-progress", ProgressBar).update(progress=0, total=100)
        except Exception:
            pass

        # Clear target input
        try:
            self.query_one("#target-input", Input).value = ""
        except Exception:
            pass

        # Update nav button active states
        for m in ("bite", "venom", "web"):
            try:
                btn = self.query_one(f"#nav-{m}")
                btn.set_class(m == mode, "active")
            except NoMatches:
                pass

        # Update BITE button label
        labels = {"bite": "BITE", "venom": "VENOM", "web": "WEB"}
        try:
            self.query_one("#btn-bite", Button).label = labels.get(mode, "BITE")
        except NoMatches:
            pass

        self._update_status()
        self._log(f"[bold green]── {mode.upper()} FANG[/bold green]  [dim]ready. enter target and fire.[/dim]")

    def on_paste(self, event) -> None:
        """Route paste to whichever Input has focus."""
        try:
            focused = self.focused
            if isinstance(focused, Input):
                pos = focused.cursor_position
                current = focused.value
                focused.value = current[:pos] + event.text + current[pos:]
                focused.cursor_position = pos + len(event.text)
        except Exception:
            pass

    def action_paste_clipboard(self) -> None:
        """Paste from Windows clipboard via PowerShell."""
        try:
            import subprocess
            result = subprocess.run(
                ["powershell", "-command", "Get-Clipboard"],
                capture_output=True, text=True, timeout=2
            )
            text = result.stdout.strip()
            if text:
                focused = self.focused
                if isinstance(focused, Input):
                    pos = focused.cursor_position
                    current = focused.value
                    focused.value = current[:pos] + text + current[pos:]
                    focused.cursor_position = pos + len(text)
        except Exception:
            pass


    # ── Actions ────────────────────────────────────────────────────────────────

    def action_tab_scan(self):    self.query_one("#tabs").active = "scan"
    def action_tab_history(self): self.query_one("#tabs").active = "history"; self._load_history()
    def action_tab_diff(self):
        self.query_one("#tabs").active = "diff"
        self._show_diff_targets()
    def action_tab_cve(self):     self.query_one("#tabs").active = "cve"
    def action_tab_crack(self):   self.query_one("#tabs").active = "crack"
    def action_tab_targets(self): self.query_one("#tabs").active = "targets"; self._load_targets()

    # ── Button handlers ────────────────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id

        if bid == "btn-bite":
            target = self.query_one("#target-input", Input).value.strip()
            if target and not self.scan_running:
                if self.current_mode == "web":
                    self._run_web(target)
                elif self.current_mode == "venom":
                    self._run_bite(target, full=True)
                else:
                    self._run_bite(target, full=False)

        elif bid == "btn-stop":
            self._stop_scan()

        elif bid == "btn-export":
            self._export_report()

        elif bid == "btn-diff":
            target = self.query_one("#diff-input", Input).value.strip()
            if target:
                try:
                    panel = self.query_one("#diff-content", ScrollableContainer)
                    panel.remove_children()
                    panel.mount(Label(f"[dim]loading diff for {target}...[/dim]"))
                except Exception:
                    pass
                self._run_diff(target)

        elif bid == "btn-diff-targets":
            self._show_diff_targets()

        elif bid == "btn-cve-search":
            query = self.query_one("#cve-input", Input).value.strip()
            if query:
                self._run_cve_search(query)

        elif bid == "btn-crack-paste":
            try:
                import subprocess
                result = subprocess.run(
                    ["powershell", "-command", "Get-Clipboard"],
                    capture_output=True, text=True, timeout=3
                )
                text = result.stdout.strip()
                if text:
                    inp = self.query_one("#crack-input", Input)
                    inp.value = text
                    inp.cursor_position = len(text)
                    inp.focus()
            except Exception as e:
                pass

        elif bid == "btn-crack":
            h = self.query_one("#crack-input", Input).value.strip()
            if h:
                self._run_crack(h)

        # Nav buttons — set mode and switch to scan tab
        elif bid == "nav-bite":
            self._set_mode("bite")
        elif bid == "nav-venom":
            self._set_mode("venom")
        elif bid == "nav-web":
            self._set_mode("web")
        elif bid == "nav-history":
            self.action_tab_history()
        elif bid == "nav-diff":
            self.action_tab_diff()
        elif bid == "nav-cve":
            self.action_tab_cve()
        elif bid == "nav-crack":
            self.action_tab_crack()
        elif bid == "nav-targets":
            self.action_tab_targets()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "target-input":
            target = event.value.strip()
            if target and not self.scan_running:
                if self.current_mode == "web":
                    self._run_web(target)
                elif self.current_mode == "venom":
                    self._run_bite(target, full=True)
                else:
                    self._run_bite(target, full=False)
        elif event.input.id == "cve-input":
            query = event.value.strip()
            if query:
                self._run_cve_search(query)
        elif event.input.id == "crack-input":
            h = event.value.strip()
            if h:
                self._run_crack(h)
        elif event.input.id == "diff-input":
            target = event.value.strip()
            if target:
                self._run_diff(target)

    # ── Scan runners ───────────────────────────────────────────────────────────

    def _log(self, msg: str):
        """Thread-safe log append with markup support."""
        def _do():
            try:
                log = self.query_one("#scan-log", RichLog)
                log.write(msg)
            except NoMatches:
                pass
        self._safe_call(_do)

    def _add_finding(self, severity: str, title: str, detail: str = ""):
        """Thread-safe finding append."""
        def _do():
            try:
                panel = self.query_one("#findings-panel", ScrollableContainer)
                style = SEV_STYLE.get(severity, "finding-info")
                sev_label = f"[{severity:<5}]"
                text = f"{sev_label}  {title}"
                if detail:
                    text += f"  {detail}"
                panel.mount(Label(text, classes=style))
                self.finding_count += 1
                self._update_status()
            except NoMatches:
                pass
        self._safe_call(_do)

    def _set_scanning(self, running: bool):
        def _do():
            self.scan_running = running
            try:
                self.query_one("#btn-stop").set_class(running, "visible")
            except NoMatches:
                pass
            self._update_status()
        self._safe_call(_do)

    def _update_status(self):
        try:
            target = self.current_target or "no target"
            count  = self.finding_count
            state  = "[red]SCANNING...[/red]" if self.scan_running else "[dim]ready[/dim]"
            mode_str = f"[dim]mode:[/dim][green]{self.current_mode}[/green]  · "
            self.query_one("#status-bar", Static).update(
                f" [cyan]{target}[/cyan]  ·  "
                f"{mode_str}  "
                f"[green]{count} findings[/green]  ·  "
                f"{state}  "
                f"  [dim][1]Scan [2]History [3]Diff [4]CVE [5]Crack [6]Targets [Q]uit[/dim]"
            )
        except Exception:
            pass

    def _clear_findings(self):
        def _do():
            try:
                panel = self.query_one("#findings-panel", ScrollableContainer)
                panel.remove_children()
                self.finding_count = 0
                self._update_status()
            except NoMatches:
                pass
        self._safe_call(_do)

    def _run_bite(self, target: str, full: bool = False):
        self.current_target = target
        self._clear_findings()

        def _do():
            self._set_scanning(True)
            self._log(f"[bold green]▸  {'venom' if full else 'bite'}[/bold green]  [cyan]{target}[/cyan]")
            self._log("")

            try:
                from viper.core import errors
                from viper.core.config import load as load_cfg
                from viper.core.latency import tune_timeout
                from viper.modules import scanner, recon, vuln
                import socket

                cfg = load_cfg()

                # Resolve
                try:
                    ip = errors.resolve(target)
                    self._log(f"[cyan]resolved[/cyan]  [dim]{target}[/dim] → [white]{ip}[/white]")
                except errors.ResolveError as e:
                    self._log(f"[red]error[/red]  {e.message}")
                    return

                # Auto-tune
                timeout = tune_timeout(ip)
                self._log(f"[dim]timeout tuned → {timeout:.2f}s[/dim]")
                self._log("")

                # Port scan
                port_str = "1-65535" if full else cfg.scan.ports
                port_list = scanner.parse_ports(port_str)
                self._log(f"[bold green]── PORT FANG[/bold green]  [dim]scanning {len(port_list)} ports...[/dim]")

                open_ports = []
                done = [0]
                self._stop_flag = False

                def _progress():
                    done[0] += 1
                    if done[0] % 500 == 0:
                        pct = int(done[0] / len(port_list) * 100)
                        # Update single status line instead of spamming log
                        self._safe_call(lambda p=pct, d=done[0]: self.query_one(
                            "#status-bar", Static
                        ).update(
                            f" [cyan]{target}[/cyan]  ·  mode:[green]{self.current_mode}[/green]  ·  "
                            f"[dim]scanning {p}%  {d}/{len(port_list)}[/dim]  ·  "
                            f"[red]SCANNING...[/red]  [dim][Q]uit[/dim]"
                        ) if not self._stop_flag else None)

                if self._stop_flag:
                    return

                open_ports = scanner.scan(
                    ip, port_str, timeout, cfg.scan.threads,
                    on_progress=_progress
                )
                if self._stop_flag:
                    self._log("[yellow]⚠ Scan stopped.[/yellow]")
                    return

                for p in open_ports:
                    self._log(f"  [green]OPEN[/green]  [cyan]{p.port:<6}[/cyan] [white]{p.service}[/white]")
                    sev = "MED" if p.flagged else "LOW"
                    self._add_finding(sev, f"Port {p.port} open", p.service)
                self._set_progress(len(port_list), len(port_list))
                self._log(f"[dim]  → {len(open_ports)} open ports[/dim]")
                self._log("")

                # DNS
                self._log("[bold green]── DNS FANG[/bold green]  [dim]resolving...[/dim]")
                dns = recon.dns(target)
                for rtype in ("A", "AAAA", "MX", "NS"):
                    for val in getattr(dns, rtype, []):
                        self._log(f"  [dim]{rtype:<6}[/dim] [white]{val}[/white]")
                self._log("")

                # Subdomains
                self._log("[bold green]── DNS FANG[/bold green]  [dim]enumerating subdomains...[/dim]")
                subs = recon.subdomains(target, threads=50)
                for s in subs:
                    self._log(f"  [green]✓[/green]  [cyan]{s.subdomain}[/cyan]  [dim]{s.ip}[/dim]")
                    self._add_finding("INFO", f"Subdomain: {s.subdomain}", s.ip)
                self._log(f"[dim]  → {len(subs)} subdomains[/dim]")
                self._log("")

                # Vuln
                if open_ports:
                    self._log("[bold green]── VENOM FANG[/bold green]  [dim]grabbing banners...[/dim]")
                    banners, vulns_found, missing = vuln.scan(ip, ports=[p.port for p in open_ports], timeout=3.0)
                    for v in sorted(vulns_found, key=lambda x: {"CRIT":0,"HIGH":1,"MED":2,"LOW":3}.get(x.severity,9)):
                        col = "red" if v.severity in ("CRIT","HIGH") else "yellow"
                        self._log(f"  [{col}]{v.severity}[/{col}]  [white]{v.cve}[/white]  [dim]{v.desc[:50]}[/dim]")
                        self._add_finding(v.severity, v.cve, v.desc[:50])
                    for m in missing:
                        self._log(f"  [dim]LOW   Missing: {m.header}  port {m.port}[/dim]")
                        self._add_finding("LOW", f"Missing: {m.header}", f"port {m.port}")
                    if not vulns_found and not missing:
                        self._log("[dim]  no findings[/dim]")
                    self._log("")

                # Web Fang (--all / venom)
                if full:
                    self._log("[bold green]── WEB FANG[/bold green]  [dim]fingerprinting...[/dim]")
                    from viper.modules.web import scan as web_scan
                    web = web_scan(target, timeout=6.0)
                    if web.status > 0:
                        self._log(f"  [dim]status[/dim] {web.status}  {web.url}")
                        if web.title:
                            self._log(f"  [dim]title [/dim] {web.title[:60]}")
                        for tech in web.tech[:5]:
                            self._log(f"  [green]FOUND[/green]  {tech.name}")
                            self._add_finding("INFO", f"Tech: {tech.name}")
                        for p in web.paths:
                            if p.severity in ("CRIT","HIGH","MED"):
                                self._log(f"  [{('red' if p.severity in ('CRIT','HIGH') else 'yellow')}]{p.severity}[/]  {p.path}")
                                self._add_finding(p.severity, p.path, p.desc[:50])
                    self._log("")

                # Auto-save to history
                try:
                    from viper.core.models import ScanResult, from_ports, from_dns, from_subs, from_vulns
                    from viper.core import history as hist
                    from dataclasses import asdict
                    findings = from_ports(open_ports, ip) + from_dns(dns, target) + from_subs(subs)
                    if open_ports:
                        _vf = vulns_found if "vulns_found" in locals() else []
                        _mf = missing if "missing" in locals() else []
                        findings += from_vulns(_vf, _mf)
                    sr = ScanResult(target=target, ip=ip, findings=findings,
                                    raw={"ports": [asdict(p) for p in open_ports]})
                    saved_path = hist.save(sr)
                    self._log(f"[dim]✓ saved  {len(findings)} findings → history[/dim]")
                except Exception as he:
                    self._log(f"[yellow]⚠ history save failed: {he}[/yellow]")

                self._log("[bold green]done.[/bold green]")

            except Exception as e:
                self._log(f"[red]error:[/red] {e}")
            finally:
                self._set_scanning(False)

        threading.Thread(target=_do, daemon=True).start()

    def _run_web(self, target: str):
        self.current_target = target
        self._clear_findings()

        def _do():
            self._set_scanning(True)
            self._log(f"[green]▸[/green] web {target}")
            self._log("")
            try:
                from viper.modules.web import scan as web_scan
                self._log("[green]WEB FANG[/green]  fingerprinting...")
                web = web_scan(target, timeout=6.0)
                if web.status == 0:
                    self._log("[red]no response[/red]")
                    return
                self._log(f"  [dim]status[/dim] {web.status}  {web.url}")
                if web.title:
                    self._log(f"  [dim]title [/dim] {web.title[:70]}")
                self._log("")
                self._log("[green]TECH STACK[/green]")
                for tech in web.tech:
                    self._log(f"  [green]FOUND[/green]  {tech.name}  [dim]{tech.source}[/dim]")
                    self._add_finding("INFO", f"Tech: {tech.name}")
                self._log("")
                self._log("[green]PATHS[/green]")
                for p in web.paths:
                    col = "red" if p.severity in ("CRIT","HIGH") else "yellow" if p.severity == "MED" else "dim"
                    self._log(f"  [{col}]{p.severity}[/]  {p.path}  [dim]{p.desc[:50]}[/dim]")
                    if p.severity not in ("INFO",):
                        self._add_finding(p.severity, p.path, p.desc[:50])
                self._log("")
                self._log("[green]HEADERS[/green]")
                for h in web.headers:
                    col = "red" if h.severity == "HIGH" else "yellow"
                    self._log(f"  [{col}]{h.severity}[/]  {h.header}")
                    self._add_finding(h.severity, f"Missing: {h.header}")
                if web.ssl:
                    self._log("")
                    self._log("[green]SSL[/green]")
                    self._log(f"  [dim]issuer [/dim] {web.ssl.issuer}")
                    self._log(f"  [dim]TLS    [/dim] {web.ssl.tls_version}")
                    if web.ssl.expired:
                        self._log(f"  [red]EXPIRED[/red] {web.ssl.expires}")
                        self._add_finding("CRIT", "SSL certificate expired", web.ssl.expires)
                    elif web.ssl.expiring_soon:
                        self._log(f"  [yellow]expires in {web.ssl.days_left} days[/yellow]  {web.ssl.expires}")
                        self._add_finding("HIGH", f"SSL expires in {web.ssl.days_left} days")
                    else:
                        self._log(f"  [dim]expires[/dim] {web.ssl.expires}  [dim]({web.ssl.days_left}d)[/dim]")
                self._log("")
                self._log("[green]done.[/green]")
            except Exception as e:
                self._log(f"[red]error:[/red] {e}")
            finally:
                self._set_scanning(False)

        threading.Thread(target=_do, daemon=True).start()

    def _stop_scan(self):
        self._stop_flag = True
        self.scan_running = False
        self._update_status()
        self._log("[yellow]⚠ Scan stopped.[/yellow]")

    def _set_progress(self, value: int, total: int = 100):
        """Update progress bar — call from any thread."""
        def _do():
            try:
                pb = self.query_one("#scan-progress", ProgressBar)
                pb.update(total=total, progress=value)
            except Exception:
                try:
                    # Fallback for older textual versions
                    pb = self.query_one("#scan-progress", ProgressBar)
                    pb.advance(value - pb.progress if hasattr(pb, "progress") else value)
                except Exception:
                    pass
        self._safe_call(_do)

    def _export_report(self):
        """Export current scan findings to HTML report."""
        if not self.current_target:
            self._log("[yellow]No scan to export. Run a scan first.[/yellow]")
            return

        def _do():
            try:
                from viper.core import history as hist
                from viper.output.report import render_html
                import pathlib, datetime

                sr = hist.latest(self.current_target)
                if not sr:
                    self._log("[yellow]No history found for current target.[/yellow]")
                    return

                ts       = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
                slug     = self.current_target.replace(".", "_")
                out_path = pathlib.Path.home() / "viper-reports"
                out_path.mkdir(exist_ok=True)
                html_file = out_path / f"viper_{slug}_{ts}.html"

                data = {
                    "target": sr.target, "ip": sr.ip,
                    "ports":  [{"port": int(f.target), "service": f.metadata.get("service",""), "flagged": f.metadata.get("flagged", False)}
                               for f in sr.findings if f.category == "open-port"],
                    "vulns":  [{"cve": f.title, "severity": f.severity, "desc": f.description, "port": f.target, "banner": f.metadata.get("banner","")}
                               for f in sr.findings if f.category == "cve"],
                    "subs":   [{"subdomain": f.target, "ip": f.metadata.get("ip","")}
                               for f in sr.findings if f.category == "subdomain"],
                    "social": [],
                }
                render_html(data, str(html_file))
                self._log(f"[green]✓ Report saved:[/green]  [dim]{html_file}[/dim]")
            except Exception as e:
                self._log(f"[red]Export failed: {e}[/red]")

        threading.Thread(target=_do, daemon=True).start()

    # ── History ────────────────────────────────────────────────────────────────

    def _drill_history(self, idx: int | None):
        """Load a specific scan from history and show its findings."""
        if idx is None or idx >= len(self._history_files):
            return
        target, path = self._history_files[idx]

        def _do():
            try:
                from viper.core import history as hist
                sr = hist.load(path)
                def _render():
                    try:
                        # Switch to scan tab and show findings
                        self.action_tab_scan()
                        self.query_one("#scan-log", RichLog).clear()
                        panel = self.query_one("#findings-panel", ScrollableContainer)
                        panel.remove_children()
                        self.finding_count = 0
                        self.current_target = sr.target

                        self._log(f"[bold green]── HISTORY DRILL[/bold green]  [cyan]{sr.target}[/cyan]  [dim]{sr.timestamp[:16]}[/dim]")
                        self._log(f"[dim]  ip: {sr.ip}  ·  {len(sr.findings)} findings[/dim]")
                        self._log("")

                        sev_order = {"CRIT":0,"HIGH":1,"MED":2,"LOW":3,"INFO":4}
                        for f in sorted(sr.findings, key=lambda x: sev_order.get(x.severity,5)):
                            col = {"CRIT":"red","HIGH":"red","MED":"yellow","LOW":"dim","INFO":"dim"}.get(f.severity,"dim")
                            self._log(f"  [{col}]{f.severity:<5}[/{col}]  [white]{f.title}[/white]  [dim]{f.description[:50]}[/dim]")
                            style = SEV_STYLE.get(f.severity, "finding-info")
                            panel.mount(Label(f"[{f.severity:<5}]  {f.title}", classes=style))
                            self.finding_count += 1

                        self._log("")
                        self._log(f"[dim]✓ loaded from history[/dim]")
                        self._update_status()
                    except Exception as e:
                        self._log(f"[red]error: {e}[/red]")
                self._safe_call(_render)
            except Exception as e:
                pass
        threading.Thread(target=_do, daemon=True).start()

    def _drill_target(self, idx: int | None):
        """Show scan timeline for a specific target."""
        if idx is None or idx >= len(self._target_names):
            return
        target = self._target_names[idx]

        def _do():
            try:
                from viper.core import history as hist
                scans = hist.scans_for(target)

                def _render():
                    try:
                        self.action_tab_scan()
                        self.query_one("#scan-log", RichLog).clear()
                        panel = self.query_one("#findings-panel", ScrollableContainer)
                        panel.remove_children()
                        self.finding_count = 0
                        self.current_target = target

                        self._log(f"[bold green]── TARGET TIMELINE[/bold green]  [cyan]{target}[/cyan]")
                        self._log(f"[dim]  {len(scans)} scans on record[/dim]")
                        self._log("")

                        for path in scans:
                            try:
                                sr = hist.load(path)
                                ts    = sr.timestamp[:16].replace("T","  ")
                                n     = len(sr.findings)
                                crits = len([f for f in sr.findings if f.severity == "CRIT"])
                                highs = len([f for f in sr.findings if f.severity == "HIGH"])
                                risk  = "[red]CRIT[/red]" if crits else "[yellow]HIGH[/yellow]" if highs else "[dim]LOW[/dim]"
                                self._log(f"  [dim]{ts}[/dim]  {risk}  [dim]{n} findings[/dim]")
                                panel.mount(Label(
                                    f"{ts}  {n} findings  {'⚠ ' + str(crits) + 'C' if crits else ''}",
                                    classes="finding-info"
                                ))
                                self.finding_count += 1
                            except Exception:
                                pass

                        self._log("")
                        self._log(f"[dim]Click History tab and select a scan to drill into findings.[/dim]")
                        self._update_status()
                    except Exception as e:
                        self._log(f"[red]error: {e}[/red]")
                self._safe_call(_render)
            except Exception as e:
                pass
        threading.Thread(target=_do, daemon=True).start()

    def _load_history(self):
        """Show recent scans as a timeline — newest first across all targets."""
        def _do():
            try:
                from viper.core import history as hist
                import pathlib

                # Gather all scan files across all targets, sort by mtime
                all_files = []
                for t in hist.all_targets():
                    for f in hist.scans_for(t):
                        all_files.append((f.stat().st_mtime, t, f))

                all_files.sort(reverse=True)  # newest first

                def _render():
                    try:
                        lv = self.query_one("#history-list", ListView)
                        lv.clear()
                        self._history_files = []
                        if not all_files:
                            lv.append(ListItem(Label("[dim]No scan history yet.  Run: viper bite <target>[/dim]")))
                            return
                        for _, target, f in all_files[:50]:
                            try:
                                sr = hist.load(f)
                                ts = sr.timestamp[:16].replace("T", "  ")
                                n  = len(sr.findings)
                                crits = len([x for x in sr.findings if x.severity == "CRIT"])
                                highs = len([x for x in sr.findings if x.severity == "HIGH"])
                                crit_str = f"  [red]{crits}C[/red]" if crits else ""
                                high_str = f"  [yellow]{highs}H[/yellow]" if highs else ""
                                lv.append(ListItem(Label(
                                    f"[dim]{ts}[/dim]  [cyan]{target:<26}[/cyan]  "
                                    f"[dim]{n} findings[/dim]{crit_str}{high_str}",
                                    classes="history-item"
                                )))
                                self._history_files.append((target, f))
                            except Exception:
                                pass
                    except Exception:
                        pass
                self._safe_call(_render)
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True).start()

    def _load_targets(self):
        """Show unique targets with aggregate stats and risk level."""
        def _do():
            try:
                from viper.core import history as hist

                targets = hist.all_targets()

                def _render():
                    try:
                        lv = self.query_one("#targets-list", ListView)
                        lv.clear()
                        self._target_names = []
                        if not targets:
                            lv.append(ListItem(Label("[dim]No targets tracked yet.[/dim]")))
                            return
                        for t in sorted(targets):
                            scans   = hist.scans_for(t)
                            count   = len(scans)
                            latest  = hist.latest(t)
                            if not latest:
                                continue
                            ts      = latest.timestamp[:10]
                            n       = len(latest.findings)
                            crits   = len([x for x in latest.findings if x.severity == "CRIT"])
                            highs   = len([x for x in latest.findings if x.severity == "HIGH"])
                            meds    = len([x for x in latest.findings if x.severity == "MED"])

                            # Risk level
                            if crits > 0:
                                risk = "[red]CRITICAL[/red]"
                            elif highs > 0:
                                risk = "[yellow]HIGH[/yellow]"
                            elif meds > 0:
                                risk = "[dim]MEDIUM[/dim]"
                            else:
                                risk = "[dim]LOW[/dim]"

                            lv.append(ListItem(Label(
                                f"[cyan]{t:<28}[/cyan]  "
                                f"[dim]{count} scan{'s' if count!=1 else ''}[/dim]  "
                                f"[dim]last {ts}[/dim]  "
                                f"[dim]{n} findings[/dim]  "
                                f"{risk}",
                                classes="history-item"
                            )))
                            self._target_names.append(t)
                    except Exception:
                        pass
                self._safe_call(_render)
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True).start()

    # ── Diff ───────────────────────────────────────────────────────────────────

    def _show_diff_targets(self):
        """Show all tracked targets and their scan counts."""
        def _do():
            try:
                from viper.core import history as hist
                targets = hist.all_targets()
                def _render():
                    try:
                        hint = self.query_one("#diff-hint", Static)
                        if not targets:
                            hint.update("[dim]  No history yet. Run a scan first.[/dim]")
                            return
                        parts = []
                        for t in sorted(targets):
                            count = hist.scan_count(t)
                            ready = count >= 2
                            color = "cyan" if ready else "dim"
                            parts.append(f"[{color}]{t} ({count})[/{color}]")
                        hint.update("  Tracked: " + "  ".join(parts) +
                                    "  [dim](need 2+ scans to diff)[/dim]")
                    except Exception:
                        pass
                self._safe_call(_render)
            except Exception:
                pass
        threading.Thread(target=_do, daemon=True).start()

    def _run_diff(self, target: str):
        def _do():
            try:
                from viper.core import history as hist
                from viper.core.diff import compare

                prev = hist.previous(target)
                curr = hist.latest(target)

                panel = self.query_one("#diff-content", ScrollableContainer)

                def _update(content_widgets):
                    panel.remove_children()
                    for w in content_widgets:
                        panel.mount(w)

                if not curr:
                    self._safe_call(lambda: panel.mount(
                        Label(f"[dim]No history for {target}. Run: viper bite {target}[/dim]")
                    ))
                    return

                if not prev:
                    self._safe_call(lambda: panel.mount(
                        Label(f"[dim]Only one scan for {target}. Run again to compare.[/dim]")
                    ))
                    return

                result = compare(prev, curr)
                widgets = []
                widgets.append(Label(f"[dim]prev  {result.previous[:10]}[/dim]"))
                widgets.append(Label(f"[dim]curr  {result.current[:10]}[/dim]"))
                delta = result.risk_delta()
                delta_str = f"[red]+{delta} risk[/red]" if delta > 0 else f"[green]{delta} risk[/green]" if delta < 0 else "[dim]no change[/dim]"
                widgets.append(Label(f"delta  {delta_str}"))
                widgets.append(Label(""))

                if result.new:
                    widgets.append(Label("[green]── NEW ──[/green]"))
                    for f in result.new:
                        col = "red" if f.severity in ("CRIT","HIGH") else "yellow" if f.severity == "MED" else "dim"
                        widgets.append(Label(f"  [green]+[/green] [{col}]{f.severity}[/]  {f.title}"))

                if result.closed:
                    widgets.append(Label(""))
                    widgets.append(Label("[dim]── CLOSED ──[/dim]"))
                    for f in result.closed:
                        widgets.append(Label(f"  [dim]-  {f.severity}  {f.title}[/dim]"))

                if result.changed:
                    widgets.append(Label(""))
                    widgets.append(Label("[yellow]── CHANGED ──[/yellow]"))
                    for old, new in result.changed:
                        widgets.append(Label(f"  [yellow]~[/yellow]  {old.severity} → {new.severity}  {new.title}"))

                widgets.append(Label(""))
                widgets.append(Label(
                    f"[green]+{len(result.new)} new[/green]  "
                    f"[dim]-{len(result.closed)} closed[/dim]  "
                    f"[yellow]~{len(result.changed)} changed[/yellow]  "
                    f"[dim]{len(result.stable)} stable[/dim]"
                ))

                self._safe_call(lambda: [panel.remove_children()] or [panel.mount(w) for w in widgets])

            except Exception as e:
                self._safe_call(lambda: self.query_one("#diff-content", ScrollableContainer).mount(
                    Label(f"[red]error: {e}[/red]")
                ))

        threading.Thread(target=_do, daemon=True).start()

    # ── CVE search ─────────────────────────────────────────────────────────────

    def _run_cve_search(self, query: str):
        def _do():
            try:
                from viper.core.cvedb import search, by_id
                panel = self.query_one("#cve-results", ScrollableContainer)
                self._safe_call(lambda: panel.remove_children())
                self._safe_call(lambda: panel.mount(Label("[dim]querying NVD...[/dim]")))

                is_cve_id = query.upper().startswith("CVE-")
                try:
                    if is_cve_id:
                        cves = [c for c in [by_id(query)] if c]
                    else:
                        cves = search(query, max_results=15, force_refresh=True)
                except Exception as api_err:
                    cves = []
                    def _err():
                        try:
                            panel = self.query_one("#cve-results", ScrollableContainer)
                            panel.remove_children()
                            panel.mount(Label(f"[red]API error: {api_err}[/red]"))
                            panel.mount(Label("[dim]NVD may be rate limiting. Try again in 30s.[/dim]"))
                        except Exception:
                            pass
                    self._safe_call(_err)
                    return

                def _render():
                    panel.remove_children()
                    if not cves:
                        panel.mount(Label(f"[dim]No CVEs found for: {query}[/dim]"))
                        panel.mount(Label("[dim]Try: nginx  apache  openssl  php  wordpress[/dim]"))
                        return
                    sev_colors = {"CRIT":"red","HIGH":"orange","MED":"yellow","LOW":"dim","INFO":"dim"}
                    for c in cves:
                        col = sev_colors.get(c.viper_severity, "dim")
                        panel.mount(Label(
                            f"  [{col}]{c.viper_severity:<5}[/]  "
                            f"[bold white]{c.id}[/bold white]  "
                            f"[dim]CVSS {c.cvss_score:.1f}  {c.published}[/dim]"
                        ))
                        panel.mount(Label(f"  [dim]       {c.short_desc(90)}[/dim]"))
                        panel.mount(Label(""))

                self._safe_call(_render)
            except Exception as e:
                self._safe_call(lambda: self.query_one("#cve-results", ScrollableContainer).mount(
                    Label(f"[red]error: {e}[/red]")
                ))

        threading.Thread(target=_do, daemon=True).start()

    # ── Crack ──────────────────────────────────────────────────────────────────

    def _run_crack(self, hash_input: str):
        def _do():
            try:
                from viper.modules.crack import crack
                panel = self.query_one("#crack-output", ScrollableContainer)
                self._safe_call(lambda: panel.remove_children())
                self._safe_call(lambda: panel.mount(Label("[dim]cracking...[/dim]")))

                result = crack(hash_input)

                def _render():
                    panel.remove_children()
                    panel.mount(Label(f"  [dim]type    [/dim] [white]{' / '.join(result.hash_types)}[/white]"))
                    panel.mount(Label(f"  [dim]tried   [/dim] [white]{result.words_tried:,} words[/white]"))
                    panel.mount(Label(""))
                    if result.cracked:
                        panel.mount(Label(f"  [green]CRACKED[/green]  [bold white]{result.cracked}[/bold white]  [dim]({result.algo_used})[/dim]"))
                    else:
                        panel.mount(Label("  [dim]✕ Not found in built-in wordlist.[/dim]"))
                        panel.mount(Label("  [dim]  Use: viper crack <hash> -w rockyou.txt[/dim]"))

                self._safe_call(_render)
            except Exception as e:
                self._safe_call(lambda: self.query_one("#crack-output", ScrollableContainer).mount(
                    Label(f"[red]error: {e}[/red]")
                ))

        threading.Thread(target=_do, daemon=True).start()


# ── Entry point ────────────────────────────────────────────────────────────────

def run():
    app = ViperTUI()
    app.run()


if __name__ == "__main__":
    run()
