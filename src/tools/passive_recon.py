"""Passive reconnaissance -- fills the previously-unused PASSIVE_RECON
category.

Two capabilities:

* `resolve_dns` shells out to `nslookup` (present on Windows and most Unix
  boxes) through the ToolExecutor, so it is gated by scope.checker under
  PASSIVE_RECON like every other target-touching tool.
* `crt_sh_subdomains` queries the crt.sh certificate-transparency log. That
  contacts a third-party public log, not the target, so -- like
  tools.cve_lookup -- it does not go through scope.checker. It only reads
  already-public certificate data.

Both are read-only lookups; neither sends anything intrusive at the target.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

import httpx

from scope.models import TestCategory
from tools.base import ToolExecutor

DNS_TIMEOUT_SECONDS = 60.0

_CRT_SH_ENDPOINT = "https://crt.sh/"
_ADDRESS_LINE_RE = re.compile(r"Address(?:es)?:\s*([0-9a-fA-F:.]+)")
# Continuation lines under "Addresses:" are bare indented IPs with no label.
_BARE_IP_RE = re.compile(r"^[0-9a-fA-F:.]+$")


@dataclass
class DnsResult:
    target: str
    addresses: list[str] = field(default_factory=list)


async def resolve_dns(executor: ToolExecutor, target: str) -> DnsResult:
    result = await executor.run(
        target=target,
        category=TestCategory.PASSIVE_RECON,
        command=["nslookup", target],
        timeout=DNS_TIMEOUT_SECONDS,
    )
    return _parse_nslookup(target, result.stdout)


def _parse_nslookup(target: str, raw: str) -> DnsResult:
    addresses: list[str] = []
    # nslookup echoes the resolver's own address first ("Server"/"Address" for
    # the DNS server); the answer section's addresses come after a blank line.
    # Grab every Address line, then drop the first if it's the server line.
    in_answer = False
    for line in raw.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("name:"):
            in_answer = True
            continue
        if not in_answer:
            continue
        match = _ADDRESS_LINE_RE.match(stripped)
        if match:
            addresses.append(match.group(1))
        elif _BARE_IP_RE.match(stripped):
            addresses.append(stripped)
    return DnsResult(target=target, addresses=addresses)


async def crt_sh_subdomains(hostname: str, *, client: httpx.AsyncClient | None = None) -> list[str]:
    """Subdomains of `hostname` seen in public CT logs. Returns [] on any
    lookup failure rather than raising -- passive recon is best-effort."""
    owns_client = client is None
    client = client or httpx.AsyncClient(timeout=30.0)
    try:
        response = await client.get(_CRT_SH_ENDPOINT, params={"q": f"%.{hostname}", "output": "json"})
        response.raise_for_status()
        return _parse_crt_sh(response.json(), hostname)
    except (httpx.HTTPError, ValueError):
        return []
    finally:
        if owns_client:
            await client.aclose()


def _parse_crt_sh(data: list, hostname: str) -> list[str]:
    names: set[str] = set()
    for entry in data or []:
        raw_value = entry.get("name_value", "")
        for name in raw_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            # Keep only real subdomains of the queried host.
            if name and name.endswith(hostname.lower()) and name != hostname.lower():
                names.add(name)
    return sorted(names)
