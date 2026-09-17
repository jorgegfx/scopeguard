"""Load a named scan profile (passive / recon_only / active) from
config/scan_profiles.yaml. This is what turns the profile's concurrency
cap and rate limit into an actual ToolExecutor semaphore/rate limiter --
see CLAUDE.md's "Bound concurrency" and "Rate limiting" requirements.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel


class ScanProfile(BaseModel):
    name: str
    description: str
    allowed_categories: list[str]
    max_concurrent_branches: int
    rate_limit_per_target_rps: float


def load_scan_profile(name: str, path: str | Path = "config/scan_profiles.yaml") -> ScanProfile:
    profiles = yaml.safe_load(Path(path).read_text())
    if name not in profiles:
        raise KeyError(f"unknown scan profile {name!r}; available: {sorted(profiles)}")
    return ScanProfile(name=name, **profiles[name])
