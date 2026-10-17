"""
tests/test_core.py — Core logic tests. No network. No rich.
Run: python tests/test_core.py
"""

import sys, io, hashlib, json, tempfile, pathlib, traceback
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

PASS = 0
FAIL = 0

def ok(label):
    global PASS
    PASS += 1
    print(f"  ✓  {label}")

def fail(label, reason):
    global FAIL
    FAIL += 1
    print(f"  ✗  {label}  →  {reason}")

# ── crack ──────────────────────────────────────────────────────────────────────
print("\n  CRACK")
try:
    from viper.modules.crack import crack, identify

    cases = [
        ("MD5",    "password", "5f4dcc3b5aa765d61d8327deb882cf99"),
        ("MD5",    "admin",    "21232f297a57a5a743894a0e4a801fc3"),
        ("MD5",    "123456",   "e10adc3949ba59abbe56e057f20f883e"),
        ("SHA1",   "password", "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"),
        ("SHA1",   "123456",   "7c4a8d09ca3762af61e59520943dc26494f8941b"),
        ("SHA256", "password", "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"),
        ("SHA256", "hello",    "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"),
        ("SHA384", "password", "a8b64babd0aca91a59bdbb7761b421d4f2bb38280d3a75ba0f21f2bebc45583d446c598660c94ce680c47d19c30783a7"),
        ("SHA512", "password", "b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86"),
        ("SHA512", "hello",    "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"),
    ]
    for algo, word, h in cases:
        r = crack(h)
        if r.cracked == word:
            ok(f"{algo} {word}")
        else:
            fail(f"{algo} {word}", f"got {r.cracked}")

    # Unknown hash
    r = crack("notahash")
    assert r.cracked is None and r.hash_types == ["Unknown"]
    ok("unknown hash graceful")

except Exception as e:
    fail("crack module", str(e))
    traceback.print_exc()

# ── models ─────────────────────────────────────────────────────────────────────
print("\n  MODELS")
try:
    from viper.core.models import Finding, ScanResult
    f = Finding("HIGH","Test","desc","port","open-port","80")
    assert f.key() == "port:open-port:80"
    f2 = Finding.from_dict(f.to_dict())
    assert f2.title == f.title and f2.severity == f.severity
    ok("Finding round-trip")

    sr = ScanResult("t.com", "1.2.3.4", findings=[f])
    sr2 = ScanResult.from_dict(sr.to_dict())
    assert len(sr2.findings) == 1
    assert sr.summary()["HIGH"] == 1
    ok("ScanResult round-trip")
except Exception as e:
    fail("models", str(e))

# ── diff ───────────────────────────────────────────────────────────────────────
print("\n  DIFF")
try:
    from viper.core.diff import compare
    from viper.core.models import Finding, ScanResult
    f1 = Finding("HIGH","Port 22","SSH","port","open-port","22")
    f2 = Finding("HIGH","Port 80","HTTP","port","open-port","80")
    f3 = Finding("MED", "Port 443","HTTPS","port","open-port","443")
    diff = compare(
        ScanResult("t.com","1.2.3.4", findings=[f1, f2]),
        ScanResult("t.com","1.2.3.4", findings=[f2, f3]),
    )
    assert len(diff.new)    == 1 and diff.new[0].target    == "443"
    assert len(diff.closed) == 1 and diff.closed[0].target == "22"
    assert len(diff.stable) == 1
    ok(f"compare: new={len(diff.new)} closed={len(diff.closed)} stable={len(diff.stable)} delta={diff.risk_delta()}")
except Exception as e:
    fail("diff", str(e))

# ── history ────────────────────────────────────────────────────────────────────
print("\n  HISTORY")
try:
    from viper.core import history as hist
    from viper.core.models import ScanResult, Finding
    f = Finding("LOW","test","desc","port","open-port","80")
    sr = ScanResult("viper-test-internal","127.0.0.1", findings=[f])
    path = hist.save(sr)
    loaded = hist.load(path)
    assert loaded.target == "viper-test-internal"
    assert loaded.findings[0].title == "test"
    path.unlink()
    td = path.parent
    if not list(td.iterdir()): td.rmdir()
    ok("save → load round-trip")
except Exception as e:
    fail("history", str(e))

# ── scanner ────────────────────────────────────────────────────────────────────
print("\n  SCANNER")
try:
    from viper.modules.scanner import parse_ports
    assert parse_ports("80,443") == [80, 443]
    assert parse_ports("1-5") == [1,2,3,4,5]
    assert parse_ports("22,80,1-3") == [1,2,3,22,80]
    ok("parse_ports: comma, range, mixed")
except Exception as e:
    fail("scanner", str(e))

# ── osint ──────────────────────────────────────────────────────────────────────
print("\n  OSINT")
try:
    from viper.modules.osint import email_guesses
    g = email_guesses("john", "doe", "example.com")
    assert "john.doe@example.com" in g
    assert "jdoe@example.com" in g
    ok(f"email_guesses: {len(g)} patterns")
except Exception as e:
    fail("osint", str(e))

# ── report ─────────────────────────────────────────────────────────────────────
print("\n  REPORT")
try:
    from viper.output.report import render_html, render_json
    data = {
        "target":"test.com","ip":"1.2.3.4",
        "ports":[{"port":80,"service":"HTTP","flagged":False}],
        "vulns":[], "subs":[], "social":[],
    }
    with tempfile.TemporaryDirectory() as tmp:
        hp = pathlib.Path(tmp) / "r.html"
        jp = pathlib.Path(tmp) / "r.json"
        render_html(data, str(hp))
        render_json(data, str(jp))
        assert hp.stat().st_size > 500
        j = json.loads(jp.read_text(encoding="utf-8"))
        assert j["target"] == "test.com"
    ok("HTML + JSON render")
except Exception as e:
    fail("report", str(e))

# ── vuln ───────────────────────────────────────────────────────────────────────
print("\n  VULN")
try:
    import re as _re
    from viper.modules.vuln import SIGNATURES, VulnResult
    from viper.core.models import from_vulns

    # Every signature pattern must compile.
    for pattern, *_ in SIGNATURES:
        _re.compile(pattern)
    ok(f"all {len(SIGNATURES)} signature patterns compile")

    # Known-vulnerable banners match the expected CVE.
    def match_cves(banner):
        return [cve for pat, svc, cve, sev, desc in SIGNATURES
                if _re.search(pat, banner, _re.IGNORECASE)]
    assert "CVE-2011-2523" in match_cves("220 (vsFTPd 2.3.4)")
    assert "CVE-2014-0160" in match_cves("OpenSSL/1.0.1")
    assert "CVE-2021-41773" in match_cves("Apache/2.4.49 (Unix)")
    ok("known banners match expected CVEs")

    # A clearly-patched / unrelated banner matches nothing.
    assert match_cves("nginx/1.99.0") == []
    ok("non-vulnerable banner yields no match")

    # Signature matches are presumptive and carry a sub-100 confidence.
    v = VulnResult(port=21, service="FTP", cve="CVE-2011-2523",
                   severity="CRIT", desc="Backdoor", banner="vsFTPd 2.3.4")
    assert v.presumptive is True and v.confidence < 100
    assert "presumptive" in v.display_desc.lower()
    ok("VulnResult defaults to presumptive with marker")

    # from_vulns propagates confidence and flags the finding.
    findings = from_vulns([v], [])
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == v.confidence
    assert f.metadata.get("presumptive") is True
    assert "verify" in f.description.lower()
    ok("from_vulns carries confidence + presumptive flag")
except Exception as e:
    fail("vuln", str(e))
    traceback.print_exc()

# ── passive ──────────────────────────────────────────────────────────────────────
print("\n  PASSIVE")
try:
    from viper.modules.passive import parse_crtsh, match_takeover
    from viper.core.models import from_passive_subs, from_takeovers

    # crt.sh parsing: dedupe, strip wildcards, keep only in-scope names.
    payload = json.dumps([
        {"name_value": "www.example.com\n*.example.com"},
        {"name_value": "api.example.com"},
        {"name_value": "www.example.com"},        # dup
        {"name_value": "evil.com"},               # out of scope
        {"name_value": "example.com"},            # apex, skip
    ])
    subs = parse_crtsh(payload, "example.com")
    names = {s.subdomain for s in subs}
    assert names == {"www.example.com", "api.example.com"}, names
    ok(f"parse_crtsh: dedup+scope → {sorted(names)}")

    assert parse_crtsh("not json", "example.com") == []
    ok("parse_crtsh: bad payload graceful")

    # Takeover fingerprint matching.
    t1 = match_takeover("foo.github.io", "<h1>There isn't a GitHub Pages site here</h1>")
    assert t1 and t1.vulnerable and t1.service == "GitHub Pages" and t1.confidence == 90
    ok("match_takeover: GitHub Pages (cname+body) → 90%")

    t2 = match_takeover("", "<Code>NoSuchBucket</Code>")
    assert t2 and t2.vulnerable and t2.service == "AWS/S3" and t2.confidence == 60
    ok("match_takeover: S3 body-only → 60%")

    assert match_takeover("foo.github.io", "<html>live site, all good</html>") is None
    ok("match_takeover: live site → no finding")

    # Normalizers.
    pf = from_passive_subs(subs)
    assert len(pf) == 2 and pf[0].source == "passive" and pf[0].category == "subdomain"
    t1.subdomain = "foo.example.com"
    tf = from_takeovers([t1])
    assert len(tf) == 1 and tf[0].severity == "HIGH" and tf[0].category == "takeover"
    ok("passive normalizers → Findings")
except Exception as e:
    fail("passive", str(e))
    traceback.print_exc()

# ── intel ────────────────────────────────────────────────────────────────────────
print("\n  INTEL")
try:
    import os as _os
    from viper.modules.intel import parse_shodan_host, shodan_key, shodan_host
    from viper.core.models import from_intel

    payload = json.dumps({
        "ip_str": "1.2.3.4", "org": "ExampleCorp", "os": None,
        "hostnames": ["a.example.com"], "ports": [443, 22],
        "tags": ["cloud"], "vulns": {"CVE-2021-1234": {}, "CVE-2020-9999": {}},
        "data": [
            {"port": 22, "transport": "tcp", "product": "OpenSSH", "version": "8.2", "data": "SSH-2.0-OpenSSH_8.2"},
            {"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0", "data": "HTTP/1.1 200"},
        ],
    })
    r = parse_shodan_host("1.2.3.4", payload)
    assert r.available and r.org == "ExampleCorp"
    assert r.ports == [22, 443]
    assert r.vulns == ["CVE-2020-9999", "CVE-2021-1234"]
    assert len(r.services) == 2
    ok("parse_shodan_host: ports, vulns, services")

    bad = parse_shodan_host("1.2.3.4", "<<not json>>")
    assert not bad.available and bad.error
    ok("parse_shodan_host: bad payload graceful")

    # Env var key resolution wins; absent key → unavailable (no network).
    _os.environ.pop("VIPER_SHODAN_KEY", None)
    assert shodan_key(None) == ""
    _os.environ["VIPER_SHODAN_KEY"] = "ENVKEY"
    assert shodan_key(None) == "ENVKEY"
    _os.environ.pop("VIPER_SHODAN_KEY", None)
    nokey = shodan_host("1.2.3.4", None)
    assert not nokey.available and "no API key" in nokey.error
    ok("shodan key resolution + no-key graceful")

    findings = from_intel(r)
    cats = {f.category for f in findings}
    assert "open-port" in cats and "cve" in cats
    assert all(f.source == "intel" for f in findings)
    assert from_intel(bad) == []
    ok(f"from_intel → {len(findings)} findings")
except Exception as e:
    fail("intel", str(e))
    traceback.print_exc()

# ── cvedb ────────────────────────────────────────────────────────────────────────
print("\n  CVEDB")
try:
    from viper.core.cvedb import build_cpe, cpe_for_banner, _parse_nvd_payload

    assert build_cpe("nginx", "nginx", "1.18.0") == "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
    assert build_cpe("apache", "http_server", "") == "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
    ok("build_cpe: 2.3 URI")

    label, cpe = cpe_for_banner("Server: Apache/2.4.49 (Unix)")
    assert cpe == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*", cpe
    assert label == "http_server 2.4.49"
    ok("cpe_for_banner: Apache → exact CPE")

    label2, cpe2 = cpe_for_banner("SSH-2.0-OpenSSH_8.2p1")
    assert cpe2.startswith("cpe:2.3:a:openbsd:openssh:8.2")
    ok("cpe_for_banner: OpenSSH")

    assert cpe_for_banner("totally unknown banner") == (None, None)
    ok("cpe_for_banner: unknown → (None, None)")

    # NVD payload parser (pure).
    sample = {"vulnerabilities": [{"cve": {
        "id": "CVE-2021-41773",
        "descriptions": [{"lang": "en", "value": "Path traversal in Apache 2.4.49"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
        "references": [{"url": "https://example.com"}],
        "published": "2021-10-05T00:00:00", "lastModified": "2021-11-01T00:00:00",
    }}]}
    parsed = _parse_nvd_payload(sample)
    assert len(parsed) == 1 and parsed[0].id == "CVE-2021-41773"
    assert parsed[0].viper_severity == "HIGH" and parsed[0].cvss_score == 7.5
    assert _parse_nvd_payload({}) == []
    ok("_parse_nvd_payload: fields + empty graceful")
except Exception as e:
    fail("cvedb", str(e))
    traceback.print_exc()

# ── tls ──────────────────────────────────────────────────────────────────────────
print("\n  TLS")
try:
    from viper.modules.web import tls_weakness_severity

    assert tls_weakness_severity([], False, False) is None
    ok("tls: clean config → no finding")

    sev, desc = tls_weakness_severity(["TLSv1", "TLSv1.1"], False, False)
    assert sev == "MED" and "TLSv1" in desc
    ok("tls: deprecated protocols → MED")

    sev2, _ = tls_weakness_severity([], False, True)
    assert sev2 == "HIGH"
    ok("tls: hostname mismatch → HIGH")

    sev3, d3 = tls_weakness_severity([], True, False)
    assert sev3 == "MED" and "self-signed" in d3
    ok("tls: self-signed → MED")
except Exception as e:
    fail("tls", str(e))
    traceback.print_exc()

# ── targets ────────────────────────────────────────────────────────────────────
print("\n  TARGETS")
try:
    from viper.core import targets as tgt

    assert tgt.expand("example.com") == ["example.com"]
    ok("expand: single host passthrough")

    # /30 → 2 usable hosts
    assert tgt.expand("10.0.0.0/30") == ["10.0.0.1", "10.0.0.2"]
    ok("expand: CIDR /30 → usable hosts")

    # /32 → the single address
    assert tgt.expand("10.0.0.5/32") == ["10.0.0.5"]
    ok("expand: CIDR /32 → host itself")

    assert tgt.expand("10.0.0.1-3") == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    ok("expand: dash range shorthand")

    mixed = tgt.expand("a.com, 10.0.0.0/31, a.com")
    assert mixed == ["a.com", "10.0.0.0", "10.0.0.1"]
    ok("expand: comma list, dedup, CIDR mix")

    with tempfile.TemporaryDirectory() as d:
        fp = pathlib.Path(d) / "t.txt"
        fp.write_text("# comment\na.com\n10.0.0.0/30\n\nb.com # trailing\n", encoding="utf-8")
        hosts = tgt.from_file(str(fp))
    assert hosts == ["a.com", "10.0.0.1", "10.0.0.2", "b.com"]
    ok("from_file: comments, blanks, inline # stripped")
except Exception as e:
    fail("targets", str(e))
    traceback.print_exc()

# ── exports ────────────────────────────────────────────────────────────────────
print("\n  EXPORTS")
try:
    from viper.output.report import (normalize_findings, build_markdown,
                                     build_sarif, render_csv)

    # From ScanResult-style dict.
    sr_data = {"target": "t.com", "findings": [
        {"severity": "HIGH", "title": "Takeover: x.t.com", "description": "dangling",
         "source": "passive", "category": "takeover", "target": "x.t.com", "confidence": 90},
        {"severity": "INFO", "title": "Port 80 open", "description": "HTTP",
         "source": "port", "category": "open-port", "target": "80", "confidence": 100},
    ]}
    nf = normalize_findings(sr_data)
    assert len(nf) == 2 and nf[0]["severity"] == "HIGH"
    ok("normalize_findings: ScanResult dict")

    # From raw scan dict.
    raw_data = {"target": "t.com",
                "ports": [{"port": 22, "service": "SSH", "flagged": False}],
                "vulns": [{"cve": "CVE-1", "severity": "CRIT", "desc": "x", "port": 22}],
                "takeovers": [{"subdomain": "a.t.com", "detail": "d", "confidence": 90}]}
    nf2 = normalize_findings(raw_data)
    cats = {r["category"] for r in nf2}
    assert cats == {"open-port", "cve", "takeover"}
    ok("normalize_findings: raw scan dict")

    md = build_markdown(sr_data)
    assert md.startswith("# Viper Report — t.com") and "| HIGH |" in md
    ok("build_markdown: table + header")

    sarif = build_sarif(sr_data)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["level"] == "error"   # HIGH → error
    assert sarif["runs"][0]["results"][1]["level"] == "note"    # INFO → note
    ok("build_sarif: schema + severity→level")

    with tempfile.TemporaryDirectory() as d:
        cp = pathlib.Path(d) / "f.csv"
        render_csv(sr_data, str(cp))
        txt = cp.read_text(encoding="utf-8")
    assert "severity,source,category" in txt and "x.t.com" in txt
    ok("render_csv: header + rows")
except Exception as e:
    fail("exports", str(e))
    traceback.print_exc()

# ── scope ──────────────────────────────────────────────────────────────────────
print("\n  SCOPE")
try:
    from viper.core import scope

    # Empty scope = unrestricted.
    assert scope.in_scope("anything.com", []) is True
    ok("in_scope: empty → unrestricted")

    pats = ["example.com", "*.example.com", "10.0.0.0/24", "# a comment"]
    assert scope.in_scope("example.com", pats) is True
    assert scope.in_scope("api.example.com", pats) is True
    assert scope.in_scope("evil.com", pats) is False
    assert scope.in_scope("10.0.0.55", pats) is True
    assert scope.in_scope("10.0.1.1", pats) is False
    ok("in_scope: exact, wildcard, CIDR, deny")

    # Wildcard should not match the apex.
    assert scope.in_scope("example.com", ["*.example.com"]) is False
    ok("in_scope: wildcard excludes apex")

    with tempfile.TemporaryDirectory() as d:
        sp = pathlib.Path(d) / "scope.txt"
        sp.write_text("# scope\nexample.com\n*.example.com\n", encoding="utf-8")
        allowed, enforced = scope.check("api.example.com", sp)
        assert allowed and enforced
        allowed2, enforced2 = scope.check("evil.com", sp)
        assert not allowed2 and enforced2
        # Missing file → not enforced.
        allowed3, enforced3 = scope.check("evil.com", pathlib.Path(d) / "nope.txt")
        assert allowed3 and not enforced3
    ok("check: enforced in/out + missing file")
except Exception as e:
    fail("scope", str(e))
    traceback.print_exc()

# ── result ─────────────────────────────────────────────────────────────────────
print(f"\n  {'─'*48}")
print(f"  {PASS} passed  {FAIL} failed")
if FAIL:
    print(f"  ✗ SOME TESTS FAILED")
    sys.exit(1)
else:
    print(f"  ✓ ALL TESTS PASSED")
