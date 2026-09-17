"""Shared scaffolding for LLM-backed sub-agents."""

from __future__ import annotations

from llm.client import LLMClient


class Agent:
    def __init__(self, agent_name: str, llm_client: LLMClient | None = None):
        # llm_client is optional -- not every sub-agent reasons over an LLM.
        # Recon, for instance, is deterministic nmap-output parsing.
        self._llm = llm_client
        self._agent_name = agent_name
