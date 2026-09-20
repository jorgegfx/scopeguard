import httpx
import yaml

from llm.client import LLMClient


def _write_config(tmp_path, **overrides):
    config = {
        "base_url": "http://localhost:1234/v1",
        "model": "test-model",
        "agents": {"tester": {"temperature": 0.1, "max_tool_calls": 3}},
        "concurrency": {"max_concurrent_requests": 2},
    }
    config.update(overrides)
    path = tmp_path / "llm.yaml"
    path.write_text(yaml.safe_dump(config))
    return path


def _fake_response(message: dict) -> httpx.Response:
    request = httpx.Request("POST", "http://localhost:1234/v1/chat/completions")
    return httpx.Response(200, json={"choices": [{"message": message}]}, request=request)


async def test_chat_returns_plain_content_when_no_tool_calls(tmp_path, monkeypatch):
    async def fake_post(self, url, json):
        assert "tools" not in json
        return _fake_response({"content": "all clear"})

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = LLMClient(config_path=_write_config(tmp_path))
    result = await client.chat("tester", [{"role": "user", "content": "hi"}])

    assert result.content == "all clear"
    assert result.tool_calls == []


async def test_chat_parses_tool_calls_and_sends_schema(tmp_path, monkeypatch):
    async def fake_post(self, url, json):
        assert json["tools"][0]["function"]["name"] == "do_thing"
        return _fake_response(
            {
                "content": None,
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "do_thing", "arguments": '{"x": 1}'}}
                ],
            }
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = LLMClient(config_path=_write_config(tmp_path))
    tools = [{"type": "function", "function": {"name": "do_thing", "parameters": {"type": "object", "properties": {}}}}]
    result = await client.chat("tester", [{"role": "user", "content": "hi"}], tools=tools)

    assert result.content is None
    assert len(result.tool_calls) == 1
    call = result.tool_calls[0]
    assert call.id == "call_1"
    assert call.name == "do_thing"
    assert call.arguments == {"x": 1}
    assert call.parse_error is None


async def test_chat_surfaces_malformed_tool_arguments_without_raising(tmp_path, monkeypatch):
    async def fake_post(self, url, json):
        return _fake_response(
            {
                "content": None,
                "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "do_thing", "arguments": "{not json"}}
                ],
            }
        )

    monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

    client = LLMClient(config_path=_write_config(tmp_path))
    result = await client.chat("tester", [{"role": "user", "content": "hi"}])

    assert result.tool_calls[0].arguments == {}
    assert "not json" in result.tool_calls[0].parse_error


def test_max_tool_calls_falls_back_to_default_for_unknown_agent(tmp_path):
    client = LLMClient(config_path=_write_config(tmp_path))

    assert client.max_tool_calls("tester") == 3
    assert client.max_tool_calls("unknown_agent") == 6
    assert client.max_tool_calls("unknown_agent", default=2) == 2
