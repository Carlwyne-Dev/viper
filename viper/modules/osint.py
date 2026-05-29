"""
modules/osint.py — Deep OSINT with metadata extraction and confidence scoring.
No rendering. Returns structured data only.
"""

import urllib.request
import urllib.error
import urllib.parse
import json
import re
import concurrent.futures
import datetime
from dataclasses import dataclass, field


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class PlatformProfile:
    platform:    str
    username:    str
    url:         str
    found:       bool        = False
    confidence:  int         = 0      # 0-100
    metadata:    dict        = field(default_factory=dict)
    # Common normalized fields
    bio:         str         = ""
    joined:      str         = ""     # ISO date or year
    last_active: str         = ""
    followers:   int         = 0
    following:   int         = 0
    posts:       int         = 0
    location:    str         = ""
    website:     str         = ""
    name:        str         = ""


@dataclass
class OsintResult:
    username:       str
    profiles:       list[PlatformProfile] = field(default_factory=list)
    confidence:     int                   = 0    # overall 0-100
    verdict:        str                   = ""   # "likely same person", etc.
    signals:        list[str]             = field(default_factory=list)
    interest_tags:  list[str]             = field(default_factory=list)
    activity_hint:  str                   = ""
    emails:         list[str]             = field(default_factory=list)

    @property
    def found_profiles(self) -> list[PlatformProfile]:
        return [p for p in self.profiles if p.found]

    @property
    def found_count(self) -> int:
        return len(self.found_profiles)


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _get(url: str, timeout: float = 6.0, headers: dict = None) -> tuple[int, str]:
    h = {"User-Agent": "Mozilla/5.0 (compatible; research-bot/1.0)"}
    if headers:
        h.update(headers)
    try:
        req = urllib.request.Request(url, headers=h)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(32768).decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        return e.code, ""
    except Exception:
        return 0, ""


def _get_json(url: str, timeout: float = 6.0) -> tuple[int, dict | list | None]:
    status, body = _get(url, timeout=timeout, headers={"Accept": "application/json"})
    if status == 200 and body:
        try:
            return status, json.loads(body)
        except Exception:
            pass
    return status, None


# ── Platform extractors ────────────────────────────────────────────────────────

def _github(username: str) -> PlatformProfile:
    p = PlatformProfile(
        platform="GitHub", username=username,
        url=f"https://github.com/{username}",
    )
    status, data = _get_json(f"https://api.github.com/users/{username}")
    if status == 200 and data:
        p.found      = True
        p.confidence = 95
        p.name       = data.get("name") or ""
        p.bio        = data.get("bio") or ""
        p.location   = data.get("location") or ""
        p.website    = data.get("blog") or ""
        p.followers  = data.get("followers", 0)
        p.following  = data.get("following", 0)
        p.posts      = data.get("public_repos", 0)
        created      = data.get("created_at", "")
        p.joined     = created[:10] if created else ""
        updated      = data.get("updated_at", "")
        p.last_active= updated[:10] if updated else ""
        p.metadata   = {
            "repos":        data.get("public_repos", 0),
            "gists":        data.get("public_gists", 0),
            "company":      data.get("company") or "",
            "hireable":     data.get("hireable"),
            "twitter":      data.get("twitter_username") or "",
            "type":         data.get("type", "User"),
        }
        # Pull top repos for interest tags
        _, repos = _get_json(f"https://api.github.com/users/{username}/repos?sort=stars&per_page=10")
        if repos and isinstance(repos, list):
            langs = [r.get("language") for r in repos if r.get("language")]
            topics = []
            for r in repos:
                topics += r.get("topics", [])
            p.metadata["top_languages"] = list(dict.fromkeys(langs))[:5]
            p.metadata["topics"]        = list(dict.fromkeys(topics))[:8]
            p.metadata["top_repos"]     = [
                {"name": r.get("name"), "stars": r.get("stargazers_count", 0)}
                for r in repos[:5]
            ]
    elif status == 404:
        p.found = False
    return p


def _hackernews(username: str) -> PlatformProfile:
    p = PlatformProfile(
        platform="HackerNews", username=username,
        url=f"https://news.ycombinator.com/user?id={username}",
    )
    status, data = _get_json(f"https://hacker-news.firebaseio.com/v0/user/{username}.json")
    if status == 200 and data and isinstance(data, dict):
        p.found      = True
        p.confidence = 90
        p.bio        = data.get("about", "")
        # Strip HTML from about
        p.bio        = re.sub(r"<[^>]+>", " ", p.bio).strip()
        karma        = data.get("karma", 0)
        p.followers  = karma  # karma as followers proxy
        created_ts   = data.get("created", 0)
        if created_ts:
            p.joined = datetime.datetime.fromtimestamp(created_ts).strftime("%Y-%m-%d")
        p.posts      = len(data.get("submitted", []))
        p.metadata   = {
            "karma":      karma,
            "submitted":  p.posts,
            "delay":      data.get("delay", 0),
        }
    return p


def _reddit(username: str) -> PlatformProfile:
    p = PlatformProfile(
        platform="Reddit", username=username,
        url=f"https://www.reddit.com/user/{username}",
    )
    status, data = _get_json(
        f"https://www.reddit.com/user/{username}/about.json",
        timeout=8.0,
    )
    if status == 200 and data:
        d = data.get("data", {}) if isinstance(data, dict) else {}
        if d and not d.get("is_suspended"):
            p.found      = True
            p.confidence = 90
            p.name       = d.get("subreddit", {}).get("title", "") if d.get("subreddit") else ""
            p.bio        = d.get("subreddit", {}).get("public_description", "") if d.get("subreddit") else ""
            created_ts   = d.get("created_utc", 0)
            if created_ts:
                p.joined = datetime.datetime.fromtimestamp(created_ts).strftime("%Y-%m-%d")
            p.followers  = d.get("total_karma", 0)
            p.metadata   = {
                "link_karma":    d.get("link_karma", 0),
                "comment_karma": d.get("comment_karma", 0),
                "total_karma":   d.get("total_karma", 0),
                "verified":      d.get("verified", False),
                "is_gold":       d.get("is_gold", False),
                "icon":          d.get("icon_img", ""),
            }
    elif status == 404:
        p.found = False
    return p


def _devto(username: str) -> PlatformProfile:
    p = PlatformProfile(
        platform="Dev.to", username=username,
        url=f"https://dev.to/{username}",
    )
    status, data = _get_json(f"https://dev.to/api/users/by_username?url={username}")
    if status == 200 and data and isinstance(data, dict):
        p.found      = True
        p.confidence = 85
        p.name       = data.get("name", "")
        p.bio        = data.get("summary", "")
        p.location   = data.get("location", "")
        p.website    = data.get("website_url", "")
        p.followers  = data.get("followers_count", 0)
        joined_raw   = data.get("joined_at", "")
        p.joined     = joined_raw[:10] if joined_raw else ""
        p.metadata   = {
            "twitter":        data.get("twitter_username", ""),
            "github":         data.get("github_username", ""),
            "articles":       data.get("articles_count", 0) if "articles_count" in data else 0,
            "profile_image":  data.get("profile_image", ""),
        }
    return p


def _gitlab(username: str) -> PlatformProfile:
    p = PlatformProfile(
        platform="GitLab", username=username,
        url=f"https://gitlab.com/{username}",
    )
    status, data = _get_json(f"https://gitlab.com/api/v4/users?username={username}")
    if status == 200 and data and isinstance(data, list) and data:
        d = data[0]
        p.found      = True
        p.confidence = 85
        p.name       = d.get("name", "")
        p.bio        = d.get("bio", "") or d.get("bio_html", "")
        p.bio        = re.sub(r"<[^>]+>", "", p.bio).strip()
        p.location   = d.get("location", "")
        p.website    = d.get("website_url", "")
        p.followers  = d.get("followers", 0)
        p.following  = d.get("following", 0)
        created      = d.get("created_at", "")
        p.joined     = created[:10] if created else ""
        p.metadata   = {
            "state":      d.get("state", ""),
            "public_email": d.get("public_email", ""),
            "work":       d.get("work_information", ""),
        }
    return p


def _existence_check(platform: str, url: str, username: str) -> PlatformProfile:
    """Fallback — HTTP existence check for platforms without APIs."""
    p = PlatformProfile(platform=platform, username=username, url=url)
    status, body = _get(url)
    if status == 200:
        p.found      = True
        p.confidence = 60  # lower — just HTTP 200, no metadata
        # Try scraping name/bio from page title
        title = re.search(r"<title[^>]*>([^<]{1,120})</title>", body, re.I)
        if title:
            p.metadata["page_title"] = title.group(1).strip()
    return p


# Platform registry
PLATFORMS = {
    "GitHub":     _github,
    "HackerNews": _hackernews,
    "Reddit":     _reddit,
    "Dev.to":     _devto,
    "GitLab":     _gitlab,
    # Existence-only checks
    "Twitter/X":  lambda u: _existence_check("Twitter/X",  f"https://twitter.com/{u}", u),
    "Instagram":  lambda u: _existence_check("Instagram",  f"https://www.instagram.com/{u}/", u),
    "Medium":     lambda u: _existence_check("Medium",     f"https://medium.com/@{u}", u),
    "TikTok":     lambda u: _existence_check("TikTok",     f"https://www.tiktok.com/@{u}", u),
    "LinkedIn":   lambda u: _existence_check("LinkedIn",   f"https://www.linkedin.com/in/{u}", u),
}


# ── Confidence scorer ──────────────────────────────────────────────────────────

def _score(profiles: list[PlatformProfile], username: str) -> tuple[int, str, list[str], list[str]]:
    """
    Returns (overall_confidence, verdict, signals, interest_tags)
    """
    found = [p for p in profiles if p.found]
    if not found:
        return 0, "no profiles found", [], []

    signals = []
    score   = 0

    # Base: number of platforms found
    ratio = len(found) / len(profiles)
    if ratio >= 0.7:
        score += 30
        signals.append(f"Found on {len(found)}/{len(profiles)} platforms")
    elif ratio >= 0.4:
        score += 15
        signals.append(f"Found on {len(found)}/{len(profiles)} platforms")
    else:
        score += 5

    # API-verified profiles (higher confidence sources)
    api_verified = [p for p in found if p.confidence >= 85]
    if api_verified:
        score += 20
        signals.append(f"{len(api_verified)} API-verified profiles")

    # Consistent real name across platforms
    names = [p.name.strip().lower() for p in found if p.name.strip()]
    if len(names) >= 2:
        unique_names = set(names)
        if len(unique_names) == 1:
            score += 15
            signals.append(f"Consistent name: {found[0].name}")
        elif len(unique_names) <= 2:
            score += 8
            signals.append("Similar names across platforms")

    # Consistent bio/description
    bios = [p.bio.strip().lower() for p in found if p.bio.strip() and len(p.bio) > 10]
    if len(bios) >= 2:
        # Check for shared words
        bio_words = [set(b.split()) for b in bios]
        if len(bio_words) >= 2:
            common = bio_words[0].intersection(*bio_words[1:])
            meaningful = {w for w in common if len(w) > 4}
            if len(meaningful) >= 3:
                score += 15
                signals.append("Consistent bio across platforms")
            elif len(meaningful) >= 1:
                score += 7

    # Consistent join year
    years = []
    for p in found:
        if p.joined and len(p.joined) >= 4:
            try:
                years.append(int(p.joined[:4]))
            except ValueError:
                pass
    if len(years) >= 2:
        year_range = max(years) - min(years)
        if year_range <= 1:
            score += 10
            signals.append(f"Accounts created around {min(years)}")
        elif year_range <= 3:
            score += 5

    # Cross-platform references (GitHub mentions Twitter, etc.)
    cross_refs = 0
    for p in found:
        if p.platform == "GitHub" and p.metadata.get("twitter"):
            cross_refs += 1
        if p.platform == "Dev.to" and p.metadata.get("github"):
            cross_refs += 1
    if cross_refs:
        score += 10
        signals.append(f"{cross_refs} cross-platform references found")

    # Location consistency
    locations = [p.location.strip().lower() for p in found if p.location.strip()]
    if len(locations) >= 2:
        if len(set(locations)) == 1:
            score += 5
            signals.append(f"Location: {found[0].location}")

    # Interest tags from GitHub
    gh = next((p for p in found if p.platform == "GitHub"), None)
    interest_tags = []
    if gh:
        langs  = gh.metadata.get("top_languages", [])
        topics = gh.metadata.get("topics", [])
        interest_tags = langs + [t for t in topics if t not in langs]
        if langs:
            signals.append(f"Languages: {', '.join(langs[:3])}")

    # Clamp score
    score = min(score, 98)

    # Verdict
    if score >= 80:
        verdict = "very likely same person across platforms"
    elif score >= 60:
        verdict = "likely same person across platforms"
    elif score >= 40:
        verdict = "possibly same person — insufficient data to confirm"
    elif score >= 20:
        verdict = "username exists but identity unclear"
    else:
        verdict = "weak signal — may be coincidental username matches"

    return score, verdict, signals, interest_tags[:8]


# ── Activity hint ──────────────────────────────────────────────────────────────

def _activity_hint(profiles: list[PlatformProfile]) -> str:
    """Best guess at activity level from metadata."""
    gh = next((p for p in profiles if p.platform == "GitHub" and p.found), None)
    hn = next((p for p in profiles if p.platform == "HackerNews" and p.found), None)
    rd = next((p for p in profiles if p.platform == "Reddit" and p.found), None)

    hints = []

    if gh and gh.last_active:
        try:
            d = datetime.datetime.strptime(gh.last_active, "%Y-%m-%d")
            days = (datetime.datetime.now() - d).days
            if days <= 7:
                hints.append("active on GitHub this week")
            elif days <= 30:
                hints.append("active on GitHub this month")
            elif days <= 180:
                hints.append("active on GitHub recently")
            else:
                hints.append(f"GitHub last active {gh.last_active}")
        except Exception:
            pass

    if hn and hn.metadata.get("karma", 0) > 1000:
        hints.append(f"HN karma {hn.metadata['karma']:,}")

    if rd and rd.metadata.get("total_karma", 0) > 1000:
        hints.append(f"Reddit karma {rd.metadata['total_karma']:,}")

    return "  ·  ".join(hints) if hints else ""


# ── Main entry points ──────────────────────────────────────────────────────────

def social(username: str, threads: int = 10) -> OsintResult:
    """
    Full deep OSINT on a username.
    Returns OsintResult with metadata, confidence scoring, and signals.
    """
    result = OsintResult(username=username)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(extractor, username): name
            for name, extractor in PLATFORMS.items()
        }
        for future in concurrent.futures.as_completed(futures):
            try:
                profile = future.result()
                result.profiles.append(profile)
            except Exception:
                pass

    # Sort: found first, then by platform name
    result.profiles.sort(key=lambda p: (not p.found, p.platform))

    # Score
    result.confidence, result.verdict, result.signals, result.interest_tags = \
        _score(result.profiles, username)

    # Activity
    result.activity_hint = _activity_hint(result.profiles)

    return result


# ── Email patterns (unchanged) ────────────────────────────────────────────────

EMAIL_PATTERNS = [
    "{first}.{last}@{domain}", "{first}{last}@{domain}",
    "{f}{last}@{domain}",      "{first}@{domain}",
    "{last}@{domain}",         "{first}_{last}@{domain}",
    "{first}-{last}@{domain}",
]

def email_guesses(first: str, last: str, domain: str) -> list[str]:
    f = first[0] if first else ""
    return [
        p.format(first=first.lower(), last=last.lower(), f=f, domain=domain)
        for p in EMAIL_PATTERNS
    ]
