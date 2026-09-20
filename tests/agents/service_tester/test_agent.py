from agents.service_tester.agent import ServiceTesterAgent, ToolSpec
from llm.client import ChatResult, ToolCall
from orchestrator.state import Severity


class _FakeLLM:
    def __init__(self, results: list[ChatResult]):
        self._results = list(results)
        self.calls: list[list[dict]] = []

    def max_tool_calls(self, agent_name: str, default: int = 6) -> int:
        return 6

    async def chat(self, agent_name, messages, tools=None):
        self.calls.append(messages)
        return self._results.pop(0)


def _tool(name="enumerate_service", handler=None):
    return ToolSpec(
        name=name,
        description="a tool",
        category="service_enum",
        handler=handler or (lambda: _ok()),
    )


async def _ok():
    return "raw nmap output"


async def test_calls_investigation_tool_then_records_finding_then_finishes():
    llm = _FakeLLM(
        [
            ChatResult(content=None, tool_calls=[ToolCall(id="1", name="enumerate_service", arguments={})]),
            ChatResult(
                content=None,
                tool_calls=[
                    ToolCall(
                        id="2",
                        name="report_finding",
                        arguments={"title": "t", "severity": "medium", "description": "d"},
                    )
                ],
            ),
            ChatResult(content="done", tool_calls=[]),
        ]
    )
    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=llm)

    findings = await agent.run("10.0.0.5", 80, "http", [_tool()])

    assert len(findings) == 1
    assert findings[0].title == "t"
    assert findings[0].severity == Severity.MEDIUM
    assert len(llm.calls) == 3


async def test_finishes_immediately_with_no_tool_calls():
    llm = _FakeLLM([ChatResult(content="nothing to see here", tool_calls=[])])
    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=llm)

    findings = await agent.run("10.0.0.5", 22, "ssh", [_tool()])

    assert findings == []


async def test_a_failing_tool_feeds_the_error_back_instead_of_raising():
    async def boom():
        raise RuntimeError("nmap not found")

    llm = _FakeLLM(
        [
            ChatResult(content=None, tool_calls=[ToolCall(id="1", name="enumerate_service", arguments={})]),
            ChatResult(content="ok, giving up", tool_calls=[]),
        ]
    )
    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=llm)

    findings = await agent.run("10.0.0.5", 80, "http", [_tool(handler=boom)])

    assert findings == []
    tool_message = llm.calls[1][-1]
    assert tool_message["role"] == "tool"
    assert "nmap not found" in tool_message["content"]


async def test_unknown_tool_name_is_reported_as_an_error_not_raised():
    llm = _FakeLLM(
        [
            ChatResult(content=None, tool_calls=[ToolCall(id="1", name="does_not_exist", arguments={})]),
            ChatResult(content="done", tool_calls=[]),
        ]
    )
    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=llm)

    findings = await agent.run("10.0.0.5", 80, "http", [_tool()])

    assert findings == []
    assert "unknown tool" in llm.calls[1][-1]["content"]


async def test_malformed_tool_call_arguments_are_reported_not_raised():
    llm = _FakeLLM(
        [
            ChatResult(content=None, tool_calls=[ToolCall(id="1", name="foo", arguments={}, parse_error="bad json")]),
            ChatResult(content="done", tool_calls=[]),
        ]
    )
    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=llm)

    findings = await agent.run("10.0.0.5", 80, "http", [_tool()])

    assert findings == []
    assert "bad json" in llm.calls[1][-1]["content"]


async def test_invalid_report_finding_arguments_are_reported_not_raised():
    llm = _FakeLLM(
        [
            ChatResult(
                content=None,
                tool_calls=[ToolCall(id="1", name="report_finding", arguments={"title": "t"})],
            ),
            ChatResult(content="done", tool_calls=[]),
        ]
    )
    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=llm)

    findings = await agent.run("10.0.0.5", 80, "http", [_tool()])

    assert findings == []
    assert "invalid report_finding arguments" in llm.calls[1][-1]["content"]


async def test_stops_after_max_steps_even_if_model_keeps_calling_tools():
    llm = _FakeLLM(
        [ChatResult(content=None, tool_calls=[ToolCall(id=str(i), name="enumerate_service", arguments={})]) for i in range(10)]
    )
    agent = ServiceTesterAgent(agent_name="service_tester", llm_client=llm)

    findings = await agent.run("10.0.0.5", 80, "http", [_tool()], max_steps=3)

    assert findings == []
    assert len(llm.calls) == 3


async def test_raises_when_constructed_without_an_llm_client():
    agent = ServiceTesterAgent(agent_name="service_tester")

    try:
        await agent.run("10.0.0.5", 80, "http", [_tool()])
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "llm_client" in str(exc)
