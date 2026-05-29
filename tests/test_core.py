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

# ── result ─────────────────────────────────────────────────────────────────────
print(f"\n  {'─'*48}")
print(f"  {PASS} passed  {FAIL} failed")
if FAIL:
    print(f"  ✗ SOME TESTS FAILED")
    sys.exit(1)
else:
    print(f"  ✓ ALL TESTS PASSED")
