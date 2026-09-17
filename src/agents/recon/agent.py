"""Recon sub-agent: nmap-based service discovery, gated through scope.checker
via tools.nmap / tools.base.ToolExecutor.

Deterministic, no LLM call -- turning nmap output into a service list is a
parsing problem, not a reasoning one. The LLM's place is one layer up, in
agents that decide what to do with what recon found.
"""

from __future__ import annotations

from agents.base import Agent
from orchestrator.state import ServiceTarget
from tools import nmap
from tools.base import ToolExecutor


class ReconAgent(Agent):
    async def run(self, executor: ToolExecutor, target: str) -> list[ServiceTarget]:
        open_ports = await nmap.scan_target(executor, target)
        return [
            ServiceTarget(target=target, port=p.port, service=p.service)
            for p in open_ports
        ]
