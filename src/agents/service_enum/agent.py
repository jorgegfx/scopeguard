"""Service/version enumeration sub-agent: deeper fingerprinting (nmap
default scripts, -sC) beyond recon's initial -sV port/version scan.

Deterministic, no LLM call -- same rationale as ReconAgent.
"""

from __future__ import annotations

from agents.base import Agent
from orchestrator.state import Finding, Severity
from tools import nmap
from tools.base import ToolExecutor


class ServiceEnumAgent(Agent):
    async def run(self, executor: ToolExecutor, target: str, port: int, service: str | None) -> list[Finding]:
        raw_output = await nmap.enumerate_service(executor, target, port)

        title = f"Service enumeration for port {port}"
        if service:
            title += f" ({service})"

        return [
            Finding(
                title=title,
                severity=Severity.INFO,
                description=f"nmap default scripts (-sC) run against {target}:{port}.",
                evidence=raw_output,
            )
        ]
