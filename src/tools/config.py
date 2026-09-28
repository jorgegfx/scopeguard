"""Per-tool subprocess timeouts, loaded from config/tools.yaml.

This is the per-command wall-clock budget axis, kept separate from
orchestrator.profiles (which loads the concurrency / rate-limit / category
axis from config/scan_profiles.yaml). Injected into ToolExecutor at run
start the same way the semaphore and rate limiter are, so a tool function
asks the executor for its budget rather than hardcoding a constant.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

# ToolExecutor's fallback for quick commands like curl.
DEFAULT_TIMEOUT_SECONDS = 120.0

# Built-in per-tool budgets, used when config/tools.yaml doesn't override them
# and when no config is loaded at all (tests, one-off scripts). nmap needs far
# more than the default: a single-host `-sV` run has been observed taking
# ~785s in practice, and the default would kill it mid-scan and misreport it
# as a recon failure.
_BUILTIN_PER_TOOL: dict[str, float] = {
    "nmap": 1200.0,
}


class ToolTimeouts(BaseModel):
    default: float = DEFAULT_TIMEOUT_SECONDS
    per_tool: dict[str, float] = Field(default_factory=lambda: dict(_BUILTIN_PER_TOOL))

    def for_tool(self, name: str) -> float:
        return self.per_tool.get(name, self.default)


def load_tool_timeouts(path: str | Path = "config/tools.yaml") -> ToolTimeouts:
    """Load timeouts from config/tools.yaml, falling back to built-in defaults.

    A missing file is not an error -- callers that don't ship a tools.yaml
    (and tests) get the built-in budgets. Any key under `timeouts:` other than
    `default` is treated as a tool name and overrides the built-in for it.
    """
    config_path = Path(path)
    if not config_path.exists():
        return ToolTimeouts()

    raw = yaml.safe_load(config_path.read_text()) or {}
    section = raw.get("timeouts", {}) or {}

    per_tool = dict(_BUILTIN_PER_TOOL)
    default = DEFAULT_TIMEOUT_SECONDS
    for key, value in section.items():
        if key == "default":
            default = float(value)
        else:
            per_tool[key] = float(value)

    return ToolTimeouts(default=default, per_tool=per_tool)
