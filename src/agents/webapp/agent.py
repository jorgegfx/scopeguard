"""Web-app specific testing sub-agent: passive HTTP-layer probing via curl,
gated through scope.checker. No payload injection or exploitation -- see
CLAUDE.md ("Keep the default toolset to discovery/enumeration...").
"""

from __future__ import annotations

from agents.base import Agent
from orchestrator.state import Finding, Severity
from tools import curl
from tools.base import ToolExecutor


class WebAppAgent(Agent):
    async def run(self, executor: ToolExecutor, target: str, port: int) -> list[Finding]:
        scheme = "https" if port == 443 else "http"
        result = await curl.probe(executor, target, port, scheme=scheme)

        description_parts = [f"HTTP probe of {result.url}"]
        if result.status_line:
            description_parts.append(result.status_line)
        if result.server_header:
            description_parts.append(f"server: {result.server_header}")
        if result.title:
            description_parts.append(f"title: {result.title!r}")

        return [
            Finding(
                title=f"HTTP service on port {port}",
                severity=Severity.INFO,
                description="; ".join(description_parts),
                evidence=result.raw_headers,
            )
        ]
