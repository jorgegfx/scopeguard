"""curl-based HTTP probe, gated through the same ToolExecutor as nmap --
CLAUDE.md calls out curl by name as a tool that must never be invoked
directly. Passive fetch only: headers + body of a single GET, no payloads.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from scope.models import TestCategory
from tools.base import ToolExecutor

_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


@dataclass
class HttpProbeResult:
    url: str
    status_line: str | None
    server_header: str | None
    title: str | None
    raw_headers: str


async def probe(executor: ToolExecutor, target: str, port: int, scheme: str = "http") -> HttpProbeResult:
    url = f"{scheme}://{target}:{port}/"
    result = await executor.run(
        target=target,
        category=TestCategory.WEBAPP_TEST,
        command=["curl", "-s", "-D", "-", "-o", "-", "--max-time", "10", url],
    )
    return _parse_curl_output(url, result.stdout)


def _parse_curl_output(url: str, raw: str) -> HttpProbeResult:
    head, sep, body = raw.partition("\r\n\r\n")
    if not sep:
        head, _, body = raw.partition("\n\n")

    lines = head.splitlines()
    status_line = lines[0] if lines else None
    server_header = None
    for line in lines[1:]:
        if line.lower().startswith("server:"):
            server_header = line.split(":", 1)[1].strip()
            break

    title_match = _TITLE_RE.search(body)
    title = title_match.group(1).strip() if title_match else None

    return HttpProbeResult(url=url, status_line=status_line, server_header=server_header, title=title, raw_headers=head)
