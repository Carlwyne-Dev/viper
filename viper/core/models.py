"""
core/models.py — Unified data model for Viper.

Everything Viper finds gets normalized into these shapes.
Modules return their own structs. The bite flows convert them here.
History, comparison, and reporting all speak this language.
"""

from __future__ import annotations
import datetime
from dataclasses import dataclass, field, asdict
from typing import Any


# ── Finding ────────────────────────────────────────────────────────────────────

SEVERITY_RANK = {"CRIT": 0, "HIGH": 1, "MED": 2, "LOW": 3, "INFO": 4}

@dataclass
class Finding:
    severity:    str            # CRIT | HIGH | MED | LOW | INFO
    title:       str            # Short label — shown in diffs and summaries
    description: str            # Human detail
    source:      str            # Which fang: port | dns | vuln | web | osint
    category:    str            # open-port | subdomain | cve | path | header | ssl | social
    target:      str            # What it applies to: port number, path, domain, username
    confidence:  int  = 100     # 0–100. 100 = certain, <80 = inferred
    metadata:    dict = field(default_factory=dict)  # banner, status, ip, etc.

    def key(self) -> str:
        """Stable identity key for comparison across scans."""
        return f"{self.source}:{self.category}:{self.target}"

    def to_dict(self) -> dict:
        return asdict(self)

    @staticmethod
    def from_dict(d: dict) -> "Finding":
        return Finding(**{k: v for k, v in d.items() if k in Finding.__dataclass_fields__})


# ── ScanResult ────────────────────────────────────────────────────────────────

@dataclass
class ScanResult:
    target:    str
    ip:        str
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())
    duration:  float = 0.0
    findings:  list[Finding] = field(default_factory=list)
    # Raw sections for report rendering
    raw:       dict = field(default_factory=dict)

    def by_severity(self, severity: str) -> list[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def by_source(self, source: str) -> list[Finding]:
        return [f for f in self.findings if f.source == source]

    def by_category(self, category: str) -> list[Finding]:
        return [f for f in self.findings if f.category == category]

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.source, f.title))

    def summary(self) -> dict:
        return {
            sev: len(self.by_severity(sev))
            for sev in ("CRIT", "HIGH", "MED", "LOW", "INFO")
        }

    def to_dict(self) -> dict:
        return {
            "target":    self.target,
            "ip":        self.ip,
            "timestamp": self.timestamp,
            "duration":  self.duration,
            "summary":   self.summary(),
            "findings":  [f.to_dict() for f in self.findings],
            "raw":       self.raw,
        }

    @staticmethod
    def from_dict(d: dict) -> "ScanResult":
        findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        return ScanResult(
            target=d["target"], ip=d.get("ip",""),
            timestamp=d.get("timestamp",""), duration=d.get("duration", 0.0),
            findings=findings, raw=d.get("raw", {}),
        )


# ── Normalizers — convert module structs → Findings ───────────────────────────

def from_ports(ports: list, ip: str = "") -> list[Finding]:
    findings = []
    for p in ports:
        sev = "LOW" if not p.flagged else "MED"
        findings.append(Finding(
            severity=sev, title=f"Port {p.port} open",
            description=f"{p.service or 'unknown'} on port {p.port}",
            source="port", category="open-port",
            target=str(p.port), confidence=100,
            metadata={"service": p.service, "flagged": p.flagged, "ip": ip},
        ))
    return findings


def from_subs(subs: list) -> list[Finding]:
    return [
        Finding(
            severity="INFO", title=f"Subdomain: {s.subdomain}",
            description=f"Resolves to {s.ip}",
            source="dns", category="subdomain",
            target=s.subdomain, confidence=100,
            metadata={"ip": s.ip},
        )
        for s in subs
    ]


def from_passive_subs(subs: list) -> list[Finding]:
    """Passive (crt.sh) subdomain discoveries."""
    return [
        Finding(
            severity="INFO", title=f"Subdomain: {s.subdomain}",
            description=f"Discovered via {s.source} (certificate transparency)",
            source="passive", category="subdomain",
            target=s.subdomain, confidence=90,
            metadata={"source": s.source},
        )
        for s in subs
    ]


def from_takeovers(takeovers: list) -> list[Finding]:
    """Dangling subdomain-takeover candidates — high-value findings."""
    findings = []
    for t in takeovers:
        findings.append(Finding(
            severity="HIGH", title=f"Possible subdomain takeover: {t.subdomain}",
            description=f"{t.detail}"
                        + (f" (CNAME → {t.cname})" if t.cname else ""),
            source="passive", category="takeover",
            target=t.subdomain, confidence=t.confidence,
            metadata={"service": t.service, "cname": t.cname},
        ))
    return findings


def from_intel(intel) -> list[Finding]:
    """Passive intelligence (Shodan) → Findings. No packets touched target."""
    findings = []
    if not intel or not getattr(intel, "available", False):
        return findings
    for port in intel.ports:
        svc = next((s for s in intel.services if s.port == port), None)
        label = f"{svc.product} {svc.version}".strip() if svc else ""
        findings.append(Finding(
            severity="INFO", title=f"Port {port} (passive)",
            description=f"Known open on {intel.source}"
                        + (f" — {label}" if label else ""),
            source="intel", category="open-port",
            target=str(port), confidence=70,
            metadata={"source": intel.source, "product": label},
        ))
    for cve in intel.vulns:
        findings.append(Finding(
            severity="MED", title=cve,
            description=f"{intel.source} flags this host as affected by {cve} — verify manually",
            source="intel", category="cve",
            target=cve, confidence=60,
            metadata={"source": intel.source, "presumptive": True},
        ))
    return findings


def from_dns(dns_result, domain: str) -> list[Finding]:
    findings = []
    from dataclasses import asdict
    for rtype, vals in asdict(dns_result).items():
        for val in vals:
            findings.append(Finding(
                severity="INFO", title=f"{rtype} record",
                description=val, source="dns", category="dns-record",
                target=f"{domain}/{rtype}", confidence=100,
                metadata={"type": rtype, "value": val},
            ))
    return findings


def from_vulns(vulns: list, missing_headers: list) -> list[Finding]:
    findings = []
    for v in vulns:
        presumptive = getattr(v, "presumptive", True)
        confidence = getattr(v, "confidence", 60)
        desc = v.desc
        if presumptive:
            desc = f"{desc} — presumptive (banner match; verify manually)"
        findings.append(Finding(
            severity=v.severity, title=v.cve,
            description=desc, source="vuln", category="cve",
            target=str(v.port), confidence=confidence,
            metadata={"banner": v.banner, "service": v.service,
                      "port": v.port, "presumptive": presumptive},
        ))
    for m in missing_headers:
        findings.append(Finding(
            severity="LOW", title=f"Missing: {m.header}",
            description=f"Security header not present on port {m.port}",
            source="vuln", category="missing-header",
            target=f"port:{m.port}:{m.header}", confidence=100,
            metadata={"port": m.port},
        ))
    return findings


def from_web(web_result) -> list[Finding]:
    findings = []
    from dataclasses import asdict

    # Tech stack (INFO)
    seen = set()
    for tech in web_result.tech:
        if tech.name not in seen:
            seen.add(tech.name)
            findings.append(Finding(
                severity="INFO", title=f"Tech: {tech.name}",
                description=f"Detected via {tech.source}",
                source="web", category="tech-stack",
                target=tech.name, confidence=80,
                metadata={"source": tech.source},
            ))

    # Sensitive paths
    for p in web_result.paths:
        if p.severity != "INFO":
            findings.append(Finding(
                severity=p.severity, title=f"Exposed path: {p.path}",
                description=p.desc, source="web", category="exposed-path",
                target=p.path, confidence=95,
                metadata={"status": p.status, "size": p.size},
            ))

    # Security headers
    for h in web_result.headers:
        findings.append(Finding(
            severity=h.severity, title=f"Missing header: {h.header}",
            description=h.desc, source="web", category="missing-header",
            target=h.header, confidence=100,
            metadata={},
        ))

    # SSL
    if web_result.ssl:
        ssl = web_result.ssl
        if ssl.expired:
            findings.append(Finding(
                severity="CRIT", title="SSL certificate expired",
                description=f"Expired on {ssl.expires}",
                source="web", category="ssl",
                target="ssl", confidence=100,
                metadata={"expires": ssl.expires, "issuer": ssl.issuer},
            ))
        elif ssl.expiring_soon:
            findings.append(Finding(
                severity="HIGH", title=f"SSL expires in {ssl.days_left} days",
                description=f"Certificate expires {ssl.expires}",
                source="web", category="ssl",
                target="ssl", confidence=100,
                metadata={"days_left": ssl.days_left, "expires": ssl.expires},
            ))

        # Deeper TLS posture (weak protocols / self-signed / hostname mismatch)
        weak = getattr(ssl, "weak_protocols", []) or []
        self_signed = getattr(ssl, "self_signed", False)
        mismatch = getattr(ssl, "hostname_mismatch", False)
        if weak or self_signed or mismatch:
            try:
                from viper.modules.web import tls_weakness_severity
                verdict = tls_weakness_severity(weak, self_signed, mismatch)
            except Exception:
                verdict = None
            if verdict:
                sev, desc = verdict
                findings.append(Finding(
                    severity=sev, title="Weak TLS configuration",
                    description=desc, source="web", category="tls-config",
                    target="tls", confidence=95,
                    metadata={"weak_protocols": weak, "self_signed": self_signed,
                              "hostname_mismatch": mismatch},
                ))

    return findings
