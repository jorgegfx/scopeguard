"""LM Studio client: OpenAI-compatible /v1/chat/completions, config-driven.

A semaphore bounds concurrent requests to the local inference server,
separate from the tool-execution concurrency cap -- LM Studio is a single
local process and its real request throughput should be measured before
assuming N parallel agents means N parallel LLM calls (see CLAUDE.md).
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

import httpx
import yaml


@dataclass
class ToolCall:
    id: str
    name: str
    # If the model emitted arguments that aren't valid JSON, `arguments` is
    # {} and `parse_error` carries the raw string -- callers should feed
    # that back to the model as a tool-result error rather than crash.
    arguments: dict
    parse_error: str | None = None


@dataclass
class ChatResult:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)


class LLMClient:
    def __init__(self, config_path: str | Path = "config/llm.yaml"):
        config = yaml.safe_load(Path(config_path).read_text())
        self._model = config["model"]
        self._agent_configs = config.get("agents", {})
        max_concurrent = config.get("concurrency", {}).get("max_concurrent_requests", 1)
        self._semaphore = asyncio.Semaphore(max_concurrent)
        self._client = httpx.AsyncClient(base_url=config["base_url"], timeout=120.0)

    def max_tool_calls(self, agent_name: str, default: int = 6) -> int:
        return self._agent_configs.get(agent_name, {}).get("max_tool_calls", default)

    async def chat(self, agent_name: str, messages: list[dict], tools: list[dict] | None = None) -> ChatResult:
        agent_config = self._agent_configs.get(agent_name, {})
        payload = {
            "model": self._model,
            "messages": messages,
            "temperature": agent_config.get("temperature", 0.2),
        }
        if tools:
            payload["tools"] = tools

        async with self._semaphore:
            response = await self._client.post("/chat/completions", json=payload)
        response.raise_for_status()

        message = response.json()["choices"][0]["message"]
        return ChatResult(content=message.get("content"), tool_calls=_parse_tool_calls(message))


def _parse_tool_calls(message: dict) -> list[ToolCall]:
    calls = []
    for raw in message.get("tool_calls") or []:
        function = raw["function"]
        try:
            arguments = json.loads(function.get("arguments") or "{}")
            parse_error = None
        except json.JSONDecodeError as exc:
            arguments = {}
            parse_error = f"invalid JSON arguments {function.get('arguments')!r}: {exc}"
        calls.append(ToolCall(id=raw["id"], name=function["name"], arguments=arguments, parse_error=parse_error))
    return calls
