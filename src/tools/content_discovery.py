"""Content discovery (directory/path enumeration) via ffuf.

Requests a bounded wordlist of common paths (.git, .env, backups, admin
panels) and reports which return non-404 responses. This is enumeration --
it does not send payloads or attempt exploitation -- but it is noisier than a
single passive probe, so it runs under its own CONTENT_DISCOVERY category
(see scope.models.TestCategory) rather than webapp_test.

The wordlist is intentionally small and conservative by default; a bigger
list means more requests against a target whose blast radius the operator may
not fully understand (CLAUDE.md).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from scope.models import TestCategory
from tools.base import ToolExecutor

CONTENT_DISCOVERY_TIMEOUT_SECONDS = 900.0

DEFAULT_WORDLIST = Path("config/wordlists/common_paths.txt")

# Status codes worth surfacing: found, redirects, and auth-gated paths (a 401
# or 403 still tells you the path exists). Plain 404s are filtered out.
_MATCH_CODES = "200,204,301,302,307,401,403,405"


@dataclass
class DiscoveredPath:
    path: str
    url: str
    status: int
    length: int


async def scan(
    executor: ToolExecutor,
    target: str,
    port: int,
    scheme: str = "http",
    wordlist: str | Path = DEFAULT_WORDLIST,
) -> list[DiscoveredPath]:
    url = f"{scheme}://{target}:{port}/FUZZ"
    result = await executor.run(
        target=target,
        category=TestCategory.CONTENT_DISCOVERY,
        command=[
            "ffuf",
            "-u", url,
            "-w", str(wordlist),
            "-mc", _MATCH_CODES,
            "-of", "json",
            "-o", "-",
            "-s",
        ],
        timeout=CONTENT_DISCOVERY_TIMEOUT_SECONDS,
    )
    return _parse_ffuf_json(result.stdout)


def _parse_ffuf_json(raw: str) -> list[DiscoveredPath]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return []

    found: list[DiscoveredPath] = []
    for entry in obj.get("results") or []:
        fuzz = (entry.get("input") or {}).get("FUZZ", "")
        found.append(
            DiscoveredPath(
                path=fuzz,
                url=entry.get("url", ""),
                status=int(entry.get("status", 0)),
                length=int(entry.get("length", 0)),
            )
        )
    return found
