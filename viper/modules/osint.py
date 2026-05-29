"""
modules/osint.py — Email patterns + social footprint.
No rendering. Returns structured data only.
"""

import urllib.request
import urllib.error
import concurrent.futures
from dataclasses import dataclass

EMAIL_PATTERNS = [
    "{first}.{last}@{domain}", "{first}{last}@{domain}",
    "{f}{last}@{domain}",      "{first}@{domain}",
    "{last}@{domain}",         "{first}_{last}@{domain}",
    "{first}-{last}@{domain}",
]

PLATFORMS = {
    "GitHub":     "https://github.com/{u}",
    "GitLab":     "https://gitlab.com/{u}",
    "Twitter/X":  "https://twitter.com/{u}",
    "Instagram":  "https://www.instagram.com/{u}",
    "Reddit":     "https://www.reddit.com/user/{u}",
    "TikTok":     "https://www.tiktok.com/@{u}",
    "HackerNews": "https://news.ycombinator.com/user?id={u}",
    "Medium":     "https://medium.com/@{u}",
    "Dev.to":     "https://dev.to/{u}",
}


@dataclass
class SocialResult:
    platform: str
    url:      str
    found:    bool


def email_guesses(first: str, last: str, domain: str) -> list[str]:
    f = first[0] if first else ""
    return [
        p.format(first=first.lower(), last=last.lower(), f=f, domain=domain)
        for p in EMAIL_PATTERNS
    ]


def _check(platform: str, url: str) -> SocialResult:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Viper/0.2)"})
        with urllib.request.urlopen(req, timeout=6) as r:
            return SocialResult(platform=platform, url=url, found=r.status == 200)
    except Exception:
        return SocialResult(platform=platform, url=url, found=False)


def social(username: str) -> list[SocialResult]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        futures = {
            ex.submit(_check, name, url.format(u=username)): name
            for name, url in PLATFORMS.items()
        }
        for f in concurrent.futures.as_completed(futures):
            results.append(f.result())
    return sorted(results, key=lambda r: (not r.found, r.platform))
