"""LM Studio client: OpenAI-compatible /v1/chat/completions, config-driven.

A semaphore bounds concurrent requests to the local inference server,
separate from the tool-execution concurrency cap -- LM Studio is a single
local process and its real request throughput should be measured before
assuming N parallel agents means N parallel LLM calls (see CLAUDE.md).
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import httpx
import yaml


class LLMClient:
    def __init__(self, config_path: str | Path = "config/llm.yaml"):
        config = yaml.safe_load(Path(config_path).read_text())
        self._model = config["model"]
        self._agent_configs = config.get("agents", {})
        max_concurrent = config.get("concurrency", {}).get("max_concurrent_requests", 1)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._client = httpx.AsyncClient(base_url=config["base_url"], timeout=120.0)

    async def chat(self, agent_name: str, messages: list[dict]) -> str:
        agent_config = self._agent_configs.get(agent_name, {})
        async with self._semaphore:
            response = await self._client.post(
                "/chat/completions",
                json={
                    "model": self._model,
                    "messages": messages,
                    "temperature": agent_config.get("temperature", 0.2),
                },
            )
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
