"""
modules/crack.py — Hash identification and wordlist cracking.
No rendering. Returns structured data only.
"""

import hashlib
import re
from dataclasses import dataclass

SIGNATURES = [
    (r"^[a-f0-9]{32}$",          "MD5",         "md5"),
    (r"^[a-f0-9]{40}$",          "SHA1",        "sha1"),
    (r"^[a-f0-9]{56}$",          "SHA224",      "sha224"),
    (r"^[a-f0-9]{64}$",          "SHA256",      "sha256"),
    (r"^[a-f0-9]{96}$",          "SHA384",      "sha384"),
    (r"^[a-f0-9]{128}$",         "SHA512",      "sha512"),
    (r"^\$2[aby]\$\d+\$",        "bcrypt",      None),
    (r"^\$6\$",                   "sha512crypt", None),
    (r"^\$1\$",                   "md5crypt",    None),
    (r"^\$5\$",                   "sha256crypt", None),
    (r"^[a-f0-9]{32}:[a-f0-9]+$","MD5+salt",    None),  # salted md5 — flag it
]

# Top ~500 most common passwords. Enough for real-world weak passwords.
BUILTIN = [
    # Top 50
    "123456","password","123456789","12345678","12345","1234567","1234567890",
    "qwerty","abc123","million2","000000","1234","iloveyou","aaron431","password1",
    "qqww1122","123","omgpop","123321","654321","qwertyuiop","qwerty123","1q2w3e4r",
    "admin","letmein","monkey","login","princess","solo","passw0rd","starwars",
    "master","hello","charlie","donald","password2","qwerty1","1q2w3e","123qwe",
    "zxcvbnm","121212","123abc","dragon","test","111111","1111","sunshine",
    "shadow","superman","michael","football",
    # Common words
    "welcome","jesus","ninja","mustang","password3","hunter","basketball",
    "access","baseball","soccer","hockey","killer","george","andrew","robert",
    "jordan","harley","ranger","dakota","maggie","summer","thomas","batman",
    "pepper","michelle","yankees","joshua","angels","chelsea","thunder","dallas",
    "daniel","laptop","matrix","access14","pickle","cheese","chicken","cheese1",
    "cookie","butter","penguin","coffee","internet","secret","service","network",
    "orange","banana","apple","cherry","lemon","mango","tiger","eagle","shark",
    "snake","rabbit","horse","diamond","silver","golden","purple","violet",
    # Patterns
    "p@ssword","p@ssw0rd","passw0rd","P@ssword","Password1","Password123",
    "admin123","Admin1234","root","toor","test123","guest","default","changeme",
    "qazwsx","1qaz2wsx","!qaz2wsx","qazxsw","pass","pass1","pass12","pass123",
    "pass1234","pass12345","123pass","321","111","222","333","444","555",
    "666","777","888","999","000","11111","22222","33333","55555","77777",
    "99999","11111111","00000000","12341234","11223344","55555555","abcdef",
    "abcdefg","abcdefgh","abcdefghi","abc","abcd","qwer","zxcv","asdf",
    "asdfgh","asdfghjk","zxcvbn","zxcvbnm","qweasd","qweasdzxc","1a2b3c",
    "a1b2c3","abc123456","admin1","admin12","admin1234","letmein1","letmein2",
    "welcome1","welcome12","welcome123","security","computer","windows","linux",
    "ubuntu","debian","centos","fedora","hacker","hacking","hack","cracked",
    "testing","password!","password@","password#","1234abcd","abcd1234",
    "qwerty12","qwerty123","qwerty1234","asdf1234","zxcv1234","123qwerty",
    "abc1","abc12","abc1234","abc12345","a123456","aaa","aaaa","aaaaa",
    "aaaaaa","aaaaaaa","aaaaaaaa","love","lovely","lover","loveyou",
    "iloveyou1","iloveyou2","sexy","baby","babe","cutie","angel","devil",
    "demon","ghost","spirit","danger","power","force","energy","magic",
    "super","ultra","mega","hyper","turbo","nitro","boost","speed",
    # Common names (frequently used as passwords)
    "james","john","robert","michael","william","david","richard","joseph",
    "thomas","charles","mary","patricia","jennifer","linda","barbara",
    "jessica","sarah","karen","lisa","nancy","matthew","ryan","kevin",
    "brian","george","edward","jason","jeffrey","frank","scott","andrew",
    "elizabeth","jessica","emily","ashley","alexis","amanda","stephanie",
    "samantha","brittany","heather","amber","jessica","megan","rachel",
    # Numbers
    "123","1234","12345","123456","1234567","12345678","123456789","1234567890",
    "0987654321","987654321","87654321","7654321","654321","54321","4321","321",
    "2580","0000","1111","2222","3333","4444","5555","6666","7777","8888","9999",
    "1212","2121","1234","4321","2345","5678","6789","7890","1357","2468",
    # Sites/services (common passwords people set)
    "facebook","twitter","google","gmail","yahoo","hotmail","outlook","linkedin",
    "instagram","youtube","netflix","amazon","paypal","ebay","apple","microsoft",
    "github","reddit","discord","telegram","whatsapp","snapchat","tiktok",
]

# Deduplicate while preserving order
seen = set()
BUILTIN = [x for x in BUILTIN if not (x in seen or seen.add(x))]


@dataclass
class CrackResult:
    hash_types:   list[str]
    cracked:      str | None = None
    algo_used:    str | None = None
    words_tried:  int        = 0
    wordlist_src: str        = "builtin"


def identify(h: str) -> list[str]:
    h = h.strip()
    return [
        name for pattern, name, _ in SIGNATURES
        if re.match(pattern, h, re.IGNORECASE)
    ] or ["Unknown"]


def _crackable_algos(h: str) -> list[tuple[str, str]]:
    """Return list of (name, hashlib_algo) that match this hash and are crackable."""
    return [
        (name, algo)
        for pattern, name, algo in SIGNATURES
        if algo and re.match(pattern, h, re.IGNORECASE)
    ]


def crack(h: str, wordlist_path: str | None = None) -> CrackResult:
    h = h.strip().lower()
    types = identify(h)
    algos = _crackable_algos(h)

    if not algos:
        return CrackResult(hash_types=types, wordlist_src="n/a")

    # Load wordlist
    wordlist = BUILTIN
    src = f"builtin ({len(BUILTIN)} words)"

    if wordlist_path:
        try:
            with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            src = f"{wordlist_path} ({len(wordlist):,} words)"
        except OSError:
            src = f"builtin ({len(BUILTIN)} words)  [dim](wordlist not found, using default)[/dim]"

    # Crack: iterate words once, try each algo per word
    # More efficient: group by algo so hashlib.new() is called minimally
    tried = 0
    for word in wordlist:
        encoded = word.encode("utf-8", errors="ignore")
        for name, algo in algos:
            try:
                digest = hashlib.new(algo, encoded).hexdigest()
                tried += 1
                if digest == h:
                    return CrackResult(
                        hash_types=types, cracked=word,
                        algo_used=name, words_tried=tried, wordlist_src=src,
                    )
            except ValueError:
                continue

    return CrackResult(hash_types=types, words_tried=tried, wordlist_src=src)
