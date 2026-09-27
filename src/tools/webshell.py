"""Remote PHP/Apache webshell & backdoor detection.

Black-box, defensive: hunts for *already-installed* web backdoors on an
authorized web target -- the attacker-planted shells (c99, r57, WSO, b374k,
...) an assessment is expected to surface. It detects and validates a
backdoor's presence; it never uploads, installs, or interacts with one
beyond a passive GET, keeping this squarely in the discovery/enumeration
posture CLAUDE.md mandates for the default toolset.

Two phases, both gated under the WEBSHELL_SCAN category (so the scope-checker
re-authorizes every request, per-branch):

  1. ffuf sweeps a curated wordlist of known webshell paths (one subprocess,
     like content_discovery) and reports which respond.
  2. each responding path is fetched once with curl and its body matched
     against known webshell signatures -- this is the *validation* step: it
     distinguishes a live shell from an unrelated file that merely happens to
     sit at a shell-like path.

A path that responds but matches no signature is reported at MEDIUM
confidence (suspicious location, unconfirmed); a signature match raises it to
HIGH. Signatures are deliberately specific (shell banners, unique field
names) rather than broad heuristics like a bare ``eval(`` -- a false
"backdoor" finding is expensive.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from scope.models import TestCategory
from tools.base import ToolExecutor

WEBSHELL_TIMEOUT_SECONDS = 900.0
# Per-path body fetch is a single small GET; it needs nothing like the sweep's
# ceiling. curl's own --max-time caps the network wait; this bounds the
# subprocess overall.
BODY_FETCH_TIMEOUT_SECONDS = 30.0

DEFAULT_WORDLIST = Path("config/wordlists/php_webshells.txt")

# A webshell path returning any of these is worth fetching + fingerprinting:
# 200 = present; 401/403 = present but access-gated (still worth flagging, a
# gated shell is still a shell); redirects can front one behind auth.
_MATCH_CODES = "200,301,302,401,403"

# Body/title signatures of well-known PHP webshells. Biased toward precision:
# unique banners and field names, not generic PHP that appears in benign apps.
# Each match is a strong indicator, so any hit raises confidence to HIGH.
_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("c99shell", re.compile(r"c99\s*shell|!C99Shell", re.IGNORECASE)),
    ("r57shell", re.compile(r"r57\s*shell", re.IGNORECASE)),
    ("WSO shell", re.compile(r"Web Shell by oRb|\bWSO\s*\d", re.IGNORECASE)),
    ("b374k", re.compile(r"b374k", re.IGNORECASE)),
    ("FilesMan file manager", re.compile(r"FilesMan", re.IGNORECASE)),
    ("IndoXploit", re.compile(r"IndoXploit", re.IGNORECASE)),
    ("AlfaShell", re.compile(r"alfa\s*(shell|team|v\d)", re.IGNORECASE)),
    (
        "known shell tagline",
        re.compile(r"priv8|0byt3m1n1|Mister Spy|madspot|gel4y|Bypass Shell", re.IGNORECASE),
    ),
    (
        "safe-mode bypass banner",
        re.compile(r"safe[_\-\s]?mode\s*:?\s*(bypass|off|on)", re.IGNORECASE),
    ),
    (
        "command-execution form field",
        re.compile(r"""name\s*=\s*['"]?(cmd|command|c99shcook)['"]?""", re.IGNORECASE),
    ),
    (
        "direct-exec PHP sink in body",
        re.compile(r"\b(passthru|shell_exec|proc_open|popen)\s*\(", re.IGNORECASE),
    ),
]


class Confidence(str, Enum):
    HIGH = "high"  # a known webshell signature matched in the response body
    MEDIUM = "medium"  # a known-shell path responded, but no signature matched


@dataclass
class WebshellDetection:
    path: str
    url: str
    status: int
    confidence: Confidence
    matched_signatures: list[str] = field(default_factory=list)


@dataclass
class _Candidate:
    path: str
    url: str
    status: int


async def scan(
    executor: ToolExecutor,
    target: str,
    port: int,
    scheme: str = "http",
    wordlist: str | Path = DEFAULT_WORDLIST,
) -> list[WebshellDetection]:
    candidates = await _sweep_paths(executor, target, port, scheme, wordlist)

    detections: list[WebshellDetection] = []
    for candidate in candidates:
        body = await _fetch_body(executor, target, candidate.url)
        matched = _match_signatures(body)
        detections.append(
            WebshellDetection(
                path=candidate.path,
                url=candidate.url,
                status=candidate.status,
                confidence=Confidence.HIGH if matched else Confidence.MEDIUM,
                matched_signatures=matched,
            )
        )
    return detections


async def _sweep_paths(
    executor: ToolExecutor, target: str, port: int, scheme: str, wordlist: str | Path
) -> list[_Candidate]:
    url = f"{scheme}://{target}:{port}/FUZZ"
    result = await executor.run(
        target=target,
        category=TestCategory.WEBSHELL_SCAN,
        command=[
            "ffuf",
            "-u", url,
            "-w", str(wordlist),
            "-mc", _MATCH_CODES,
            "-of", "json",
            "-o", "-",
            "-s",
        ],
        timeout=WEBSHELL_TIMEOUT_SECONDS,
    )
    return _parse_ffuf_json(result.stdout)


async def _fetch_body(executor: ToolExecutor, target: str, url: str) -> str:
    result = await executor.run(
        target=target,
        category=TestCategory.WEBSHELL_SCAN,
        # -s: quiet; -L: follow the redirect a gated shell may sit behind;
        # body only (no -D) -- signatures are matched against the page body.
        command=["curl", "-s", "-L", "--max-time", "15", url],
        timeout=BODY_FETCH_TIMEOUT_SECONDS,
    )
    return result.stdout


def _parse_ffuf_json(raw: str) -> list[_Candidate]:
    raw = raw.strip()
    if not raw:
        return []
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return []

    candidates: list[_Candidate] = []
    for entry in obj.get("results") or []:
        fuzz = (entry.get("input") or {}).get("FUZZ", "")
        candidates.append(
            _Candidate(
                path=fuzz,
                url=entry.get("url", ""),
                status=int(entry.get("status", 0)),
            )
        )
    return candidates


def _match_signatures(body: str) -> list[str]:
    """Return the names of every webshell signature present in ``body``."""
    if not body:
        return []
    return [name for name, pattern in _SIGNATURES if pattern.search(body)]
