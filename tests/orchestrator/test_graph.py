import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agents.service_tester.agent import ServiceTesterAgent
from llm.client import ChatResult, ToolCall
from orchestrator import graph as scan_graph
from orchestrator.state import Finding, Severity
from scope.models import AuthorizationArtifact, ScopeRecord, ScopeTarget, TestCategory, TimeWindow
from tools.nmap import OpenPort
from tools.rate_limit import RateLimiter


class _FakeLLM:
    def __init__(self, results):
        self._results = list(results)

    def max_tool_calls(self, agent_name, default=6):
        return 6

    async def chat(self, agent_name, messages, tools=None):
        return self._results.pop(0)


def _scope_record(**overrides) -> ScopeRecord:
    now = datetime.now(timezone.utc)
    defaults = dict(
        run_id="graph-test-run",
        targets=[ScopeTarget(value="10.0.0.5"), ScopeTarget(value="10.0.0.9")],
        authorization=AuthorizationArtifact(kind="self_attestation", reference_id="test-1"),
        time_window=TimeWindow(starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1)),
        allowed_categories=[TestCategory.PORT_SCAN],
    )
    defaults.update(overrides)
    return ScopeRecord(**defaults)


def _base_state(scope_record: ScopeRecord, **overrides) -> dict:
    state = {
        "run_id": scope_record.run_id,
        "scope_record": scope_record,
        "discovered_services": [],
        "service_findings": [],
        "report": None,
        "tool_semaphore": asyncio.Semaphore(5),
        "rate_limiter": RateLimiter(requests_per_second=None),
        "llm_client": None,
    }
    state.update(overrides)
    return state


async def test_recon_node_discovers_services_across_all_scope_targets(monkeypatch, tmp_path):
    async def fake_scan_target(executor, target):
        return [OpenPort(port=22, protocol="tcp", service="ssh", product=None, version=None)]

    monkeypatch.setattr("agents.recon.agent.nmap.scan_target", fake_scan_target)
    monkeypatch.chdir(tmp_path)

    scope_record = _scope_record()
    result = await scan_graph.recon_node(_base_state(scope_record))

    assert result["discovered_services"] == [
        {"target": "10.0.0.5", "port": 22, "service": "ssh"},
        {"target": "10.0.0.9", "port": 22, "service": "ssh"},
    ]


async def test_recon_node_isolates_a_failing_target(monkeypatch, tmp_path):
    async def fake_scan_target(executor, target):
        if target == "10.0.0.5":
            raise TimeoutError("nmap timed out after 120.0 seconds")
        return [OpenPort(port=22, protocol="tcp", service="ssh", product=None, version=None)]

    monkeypatch.setattr("agents.recon.agent.nmap.scan_target", fake_scan_target)
    monkeypatch.chdir(tmp_path)

    scope_record = _scope_record()
    result = await scan_graph.recon_node(_base_state(scope_record))

    assert result["discovered_services"] == [{"target": "10.0.0.9", "port": 22, "service": "ssh"}]
    assert result["service_findings"] == [
        {
            "target": "10.0.0.5",
            "port": 0,
            "category": "recon",
            "findings": [],
            "error": "nmap timed out after 120.0 seconds",
        }
    ]


async def test_test_service_node_exposes_only_authorized_tools_to_the_llm(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    captured_tool_names = []

    async def fake_run(self, target, port, service, tool_specs, max_steps=None):
        captured_tool_names.extend(t.name for t in tool_specs)
        return [Finding(title="enum finding", severity=Severity.INFO, description="ok")]

    monkeypatch.setattr(ServiceTesterAgent, "run", fake_run)

    scope_record = _scope_record(
        allowed_categories=[TestCategory.SERVICE_ENUM, TestCategory.VULN_SCAN, TestCategory.WEBAPP_TEST]
    )
    state = _base_state(scope_record, target_service={"target": "10.0.0.5", "port": 80, "service": "http"})

    result = await scan_graph.test_service_node(state)

    assert set(captured_tool_names) == {"enumerate_service", "scan_vulnerabilities", "probe_http"}
    assert result["service_findings"] == [
        {
            "target": "10.0.0.5",
            "port": 80,
            "category": "llm_reasoning",
            "findings": [Finding(title="enum finding", severity=Severity.INFO, description="ok")],
            "error": None,
        }
    ]


async def test_test_service_node_skips_services_with_no_authorized_category(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    scope_record = _scope_record(allowed_categories=[TestCategory.PORT_SCAN])
    state = _base_state(scope_record, target_service={"target": "10.0.0.5", "port": 22, "service": "ssh"})

    result = await scan_graph.test_service_node(state)

    assert result["service_findings"] == []


async def test_test_service_node_fails_closed_when_the_llm_is_unreachable(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    async def fake_run(self, target, port, service, tool_specs, max_steps=None):
        raise ConnectionError("LM Studio unreachable")

    monkeypatch.setattr(ServiceTesterAgent, "run", fake_run)

    scope_record = _scope_record(allowed_categories=[TestCategory.SERVICE_ENUM])
    state = _base_state(scope_record, target_service={"target": "10.0.0.5", "port": 22, "service": "ssh"})

    result = await scan_graph.test_service_node(state)

    assert result["service_findings"] == [
        {
            "target": "10.0.0.5",
            "port": 22,
            "category": "llm_reasoning",
            "findings": [],
            "error": "LM Studio unreachable",
        }
    ]


async def test_test_service_node_end_to_end_with_a_fake_llm(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    async def fake_scan_vulnerabilities(executor, target, port):
        return "(no vulns found)"

    monkeypatch.setattr("orchestrator.graph.nmap.scan_vulnerabilities", fake_scan_vulnerabilities)

    llm = _FakeLLM(
        [
            ChatResult(content=None, tool_calls=[ToolCall(id="1", name="scan_vulnerabilities", arguments={})]),
            ChatResult(content="nothing found", tool_calls=[]),
        ]
    )
    scope_record = _scope_record(allowed_categories=[TestCategory.VULN_SCAN])
    state = _base_state(
        scope_record,
        target_service={"target": "10.0.0.5", "port": 443, "service": "https"},
        llm_client=llm,
    )

    result = await scan_graph.test_service_node(state)

    assert result["service_findings"] == [
        {"target": "10.0.0.5", "port": 443, "category": "llm_reasoning", "findings": [], "error": None}
    ]


async def test_report_node_writes_markdown_and_pdf(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    scope_record = _scope_record()
    state = _base_state(
        scope_record,
        service_findings=[
            {
                "target": "10.0.0.5",
                "port": 80,
                "category": "webapp_test",
                "findings": [Finding(title="HTTP", severity=Severity.INFO, description="ok")],
                "error": None,
            }
        ],
    )

    result = await scan_graph.report_node(state)

    assert (tmp_path / "reports" / f"{scope_record.run_id}.md").exists()
    assert (tmp_path / "reports" / f"{scope_record.run_id}.pdf").exists()
    assert Path(result["report"]).name == f"{scope_record.run_id}.md"
