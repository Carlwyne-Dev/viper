"""
modules/crack.py — Hash identification and wordlist cracking.

Cracking is offline by design: hashes are never sent to any third-party
service. Strength comes from a rule/mutation engine (case, leet, affixes) that
turns each wordlist entry into dozens of realistic variants, plus support for
salted MD5/SHA and NTLM.

No rendering. Returns structured data only.
"""

import hashlib
import re
from dataclasses import dataclass, field

SIGNATURES = [
    (r"^[a-f0-9]{32}$",          "MD5",         "md5"),
    (r"^[a-f0-9]{32}$",          "NTLM",        "ntlm"),   # same width as MD5
    (r"^[a-f0-9]{40}$",          "SHA1",        "sha1"),
    (r"^[a-f0-9]{56}$",          "SHA224",      "sha224"),
    (r"^[a-f0-9]{64}$",          "SHA256",      "sha256"),
    (r"^[a-f0-9]{96}$",          "SHA384",      "sha384"),
    (r"^[a-f0-9]{128}$",         "SHA512",      "sha512"),
    (r"^\$2[aby]\$\d+\$",        "bcrypt",      None),
    (r"^\$6\$",                   "sha512crypt", None),
    (r"^\$1\$",                   "md5crypt",    None),
    (r"^\$5\$",                   "sha256crypt", None),
]

# Algorithms we identify but cannot crack here (need john/hashcat/passlib).
NEEDS_EXTERNAL = {"bcrypt", "sha512crypt", "md5crypt", "sha256crypt"}

# ── Built-in seed wordlist ─────────────────────────────────────────────────────
# Kept intentionally small — the mutation engine expands each of these into
# many realistic candidates. Point -w at rockyou.txt for serious work.
BUILTIN = [
    "123456","password","123456789","12345678","12345","1234567","1234567890",
    "qwerty","abc123","million2","000000","1234","iloveyou","aaron431","password1",
    "qqww1122","123","omgpop","123321","654321","qwertyuiop","qwerty123","1q2w3e4r",
    "admin","letmein","monkey","login","princess","solo","passw0rd","starwars",
    "master","hello","charlie","donald","football","welcome","jesus","ninja",
    "mustang","hunter","basketball","access","baseball","soccer","hockey","killer",
    "jordan","harley","ranger","dakota","maggie","summer","batman","pepper",
    "michelle","yankees","joshua","angels","chelsea","thunder","dallas","daniel",
    "laptop","matrix","pickle","cheese","chicken","cookie","butter","penguin",
    "coffee","internet","secret","service","network","orange","banana","apple",
    "tiger","eagle","shark","snake","rabbit","horse","diamond","silver","golden",
    "purple","dragon","shadow","superman","michael","sunshine","zxcvbnm","qazwsx",
    "root","toor","test","guest","default","changeme","security","computer",
    "windows","linux","ubuntu","hacker","love","angel","george","andrew","robert",
    "thomas","james","john","william","david","richard","mary","jennifer","sarah",
    "facebook","google","gmail","yahoo","paypal","amazon","apple","github","discord",
]
# Deduplicate while preserving order.
_seen = set()
BUILTIN = [x for x in BUILTIN if not (x in _seen or _seen.add(x))]


# ── Mutation / rule engine ─────────────────────────────────────────────────────

# Common leet substitutions (one canonical mapping — kept small on purpose).
_LEET = str.maketrans({"a": "@", "e": "3", "i": "1", "o": "0", "s": "$", "t": "7"})

# Affixes people actually append/prepend. Years are generated for recency.
_YEARS = [str(y) for y in range(2015, 2027)]
_SUFFIXES = (
    ["", "1", "2", "3", "12", "123", "1234", "12345",
     "!", "@", "#", ".", "?", "01", "007", "69", "321", "00", "99", "111",
     "!@#", "123!", "1!"]
    + _YEARS
)
_PREFIXES = ["", "1", "!"]


def _base_forms(word: str):
    """Distinct casings / leet forms of a word, order-preserving & deduped."""
    forms = [
        word,
        word.lower(),
        word.upper(),
        word.capitalize(),
        word.lower().translate(_LEET),
        word.capitalize().translate(_LEET),
    ]
    seen, out = set(), []
    for f in forms:
        if f and f not in seen:
            seen.add(f)
            out.append(f)
    return out


def mutate(word: str, max_variants: int | None = None):
    """
    Yield realistic password variants of `word`: case/leet forms, each combined
    with common prefixes and suffixes (digits, years, symbols). Deduped, with an
    optional cap. Pure generator — no hashing, no network. Testable.
    """
    word = word.strip()
    if not word:
        return
    seen = set()
    count = 0
    for base in _base_forms(word):
        for pre in _PREFIXES:
            for suf in _SUFFIXES:
                cand = f"{pre}{base}{suf}"
                if cand in seen:
                    continue
                seen.add(cand)
                yield cand
                count += 1
                if max_variants is not None and count >= max_variants:
                    return


# ── Hash computation ───────────────────────────────────────────────────────────

def _md4(data: bytes) -> str:
    """MD4 digest — hashlib if available, else a pure-Python fallback.

    OpenSSL 3.0 dropped MD4, so hashlib.new('md4') often raises. NTLM needs it,
    so we ship a compact fallback to keep NTLM working everywhere.
    """
    try:
        return hashlib.new("md4", data).hexdigest()
    except (ValueError, TypeError):
        return _md4_pure(data)


def _md4_pure(msg: bytes) -> str:
    import struct
    def lrot(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
    orig_len = len(msg)
    msg += b"\x80"
    while len(msg) % 64 != 56:
        msg += b"\x00"
    msg += struct.pack("<Q", (orig_len * 8) & 0xFFFFFFFFFFFFFFFF)
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        aa, bb, cc, dd = a, b, c, d
        for i in (0, 4, 8, 12):          # round 1
            a = lrot((a + ((b & c) | (~b & d)) + X[i]) & 0xFFFFFFFF, 3)
            d = lrot((d + ((a & b) | (~a & c)) + X[i + 1]) & 0xFFFFFFFF, 7)
            c = lrot((c + ((d & a) | (~d & b)) + X[i + 2]) & 0xFFFFFFFF, 11)
            b = lrot((b + ((c & d) | (~c & a)) + X[i + 3]) & 0xFFFFFFFF, 19)
        for i in (0, 1, 2, 3):           # round 2
            a = lrot((a + ((b & c) | (b & d) | (c & d)) + X[i] + 0x5A827999) & 0xFFFFFFFF, 3)
            d = lrot((d + ((a & b) | (a & c) | (b & c)) + X[i + 4] + 0x5A827999) & 0xFFFFFFFF, 5)
            c = lrot((c + ((d & a) | (d & b) | (a & b)) + X[i + 8] + 0x5A827999) & 0xFFFFFFFF, 9)
            b = lrot((b + ((c & d) | (c & a) | (d & a)) + X[i + 12] + 0x5A827999) & 0xFFFFFFFF, 13)
        for i in (0, 2, 1, 3):           # round 3
            a = lrot((a + (b ^ c ^ d) + X[i] + 0x6ED9EBA1) & 0xFFFFFFFF, 3)
            d = lrot((d + (a ^ b ^ c) + X[i + 8] + 0x6ED9EBA1) & 0xFFFFFFFF, 9)
            c = lrot((c + (d ^ a ^ b) + X[i + 4] + 0x6ED9EBA1) & 0xFFFFFFFF, 11)
            b = lrot((b + (c ^ d ^ a) + X[i + 12] + 0x6ED9EBA1) & 0xFFFFFFFF, 15)
        a = (a + aa) & 0xFFFFFFFF
        b = (b + bb) & 0xFFFFFFFF
        c = (c + cc) & 0xFFFFFFFF
        d = (d + dd) & 0xFFFFFFFF
    return struct.pack("<4I", a, b, c, d).hex()


def hash_word(word: str, algo: str, salt: str | None = None) -> str | None:
    """Compute the hex digest of `word` under `algo` (optionally salted)."""
    try:
        if algo == "ntlm":
            return _md4(word.encode("utf-16le"))
        enc = word.encode("utf-8", errors="ignore")
        if salt is not None:
            s = salt.encode("utf-8", errors="ignore")
            # Try the common orderings; caller compares against the target.
            return hashlib.new(algo, enc + s).hexdigest()
        return hashlib.new(algo, enc).hexdigest()
    except (ValueError, TypeError):
        return None


# ── Identification ───────────────────────────────────────────────────────────

@dataclass
class CrackResult:
    hash_types:   list[str]
    cracked:      str | None = None
    algo_used:    str | None = None
    words_tried:  int        = 0
    wordlist_src: str        = "builtin"
    salted:       bool       = False
    note:         str        = ""


def _split_salt(h: str):
    """Return (digest, salt) for 'digest:salt' input, else (h, None)."""
    if ":" in h:
        left, right = h.split(":", 1)
        if re.fullmatch(r"[a-f0-9]{32}", left, re.IGNORECASE) and right:
            return left.lower(), right
    return h, None


def identify(h: str) -> list[str]:
    h = h.strip()
    digest, salt = _split_salt(h)
    names = [name for pattern, name, _ in SIGNATURES
             if re.match(pattern, digest, re.IGNORECASE)]
    if salt is not None:
        names = [f"{n}+salt" for n in names if n in ("MD5", "NTLM")] or ["salted"]
    return names or ["Unknown"]


def _crackable_algos(digest: str) -> list[tuple[str, str]]:
    return [(name, algo) for pattern, name, algo in SIGNATURES
            if algo and re.match(pattern, digest, re.IGNORECASE)]


# ── Crack ──────────────────────────────────────────────────────────────────────

def crack(h: str, wordlist_path: str | None = None,
          use_rules: bool = True) -> CrackResult:
    raw = h.strip()
    digest, salt = _split_salt(raw)
    digest = digest.lower()
    types = identify(raw)
    algos = _crackable_algos(digest)

    if not algos:
        # Identified but not crackable here?
        ext = [t for t in types if t in NEEDS_EXTERNAL]
        note = (f"{ext[0]} is not crackable offline here — use john/hashcat"
                if ext else "")
        return CrackResult(hash_types=types, wordlist_src="n/a",
                           salted=salt is not None, note=note)

    # Load wordlist.
    wordlist = BUILTIN
    src = f"builtin ({len(BUILTIN)} words)"
    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            src = f"{wordlist_path} ({len(wordlist):,} words)"
        except OSError:
            src = f"builtin ({len(BUILTIN)} words, wordlist not found)"

    tried = 0
    for word in wordlist:
        candidates = mutate(word) if use_rules else iter([word])
        for cand in candidates:
            tried += 1
            for name, algo in algos:
                if salt is not None:
                    enc = cand.encode("utf-8", errors="ignore")
                    s = salt.encode("utf-8", errors="ignore")
                    try:
                        d1 = hashlib.new(algo, enc + s).hexdigest()
                        d2 = hashlib.new(algo, s + enc).hexdigest()
                    except (ValueError, TypeError):
                        continue
                    if digest in (d1, d2):
                        return CrackResult(hash_types=types, cracked=cand,
                                           algo_used=name, words_tried=tried,
                                           wordlist_src=src, salted=True)
                else:
                    if hash_word(cand, algo) == digest:
                        return CrackResult(hash_types=types, cracked=cand,
                                           algo_used=name, words_tried=tried,
                                           wordlist_src=src, salted=False)

    return CrackResult(hash_types=types, words_tried=tried, wordlist_src=src,
                       salted=salt is not None)
