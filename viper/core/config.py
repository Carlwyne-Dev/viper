"""
core/config.py — Single source of truth for all defaults.
"""

import json
from pathlib import Path
from dataclasses import dataclass, asdict

CONFIG_PATH = Path.home() / ".viper" / "config.json"

@dataclass
class ScanConfig:
    ports:   str   = "1-1024"
    timeout: float = 0.5
    threads: int   = 150

@dataclass
class ReconConfig:
    subs_wordlist: str  = "builtin"
    whois:         bool = False

@dataclass
class OutputConfig:
    report_dir: str = "~/viper-reports"
    format:     str = "html"
    timestamp:  bool = True

@dataclass
class ViperConfig:
    scan:   ScanConfig   = None
    recon:  ReconConfig  = None
    output: OutputConfig = None

    def __post_init__(self):
        self.scan   = self.scan   or ScanConfig()
        self.recon  = self.recon  or ReconConfig()
        self.output = self.output or OutputConfig()


def load() -> ViperConfig:
    if not CONFIG_PATH.exists():
        return ViperConfig()
    try:
        raw = json.loads(CONFIG_PATH.read_text())
        cfg = ViperConfig()
        if "scan"   in raw: cfg.scan   = ScanConfig(**{k: v for k, v in raw["scan"].items()   if hasattr(ScanConfig,   k)})
        if "recon"  in raw: cfg.recon  = ReconConfig(**{k: v for k, v in raw["recon"].items() if hasattr(ReconConfig,  k)})
        if "output" in raw: cfg.output = OutputConfig(**{k: v for k, v in raw["output"].items() if hasattr(OutputConfig, k)})
        return cfg
    except Exception:
        return ViperConfig()


def save(cfg: ViperConfig):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = {
        "scan":   asdict(cfg.scan),
        "recon":  asdict(cfg.recon),
        "output": asdict(cfg.output),
    }
    CONFIG_PATH.write_text(json.dumps(data, indent=2), encoding="utf-8")


def init():
    if not CONFIG_PATH.exists():
        save(ViperConfig())
    return load()
