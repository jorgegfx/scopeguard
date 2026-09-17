import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agents.service_enum.agent import ServiceEnumAgent
from agents.vuln_scan.agent import VulnScanAgent
from agents.webapp.agent import WebAppAgent
from orchestrator import graph as scan_graph
from orchestrator.state import Finding, Severity
from scope.models import AuthorizationArtifact, ScopeRecord, ScopeTarget, TestCategory, TimeWindow
from tools.nmap import OpenPort
from tools.rate_limit import RateLimiter


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


async def test_test_service_node_runs_every_authorized_category(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    async def fake_service_enum_run(self, executor, target, port, service):
        return [Finding(title="enum", severity=Severity.INFO, description="ok")]

    async def fake_vuln_scan_run(self, executor, target, port, service):
        return []

    async def fake_webapp_run(self, executor, target, port):
        return [Finding(title="http", severity=Severity.INFO, description="ok")]

    monkeypatch.setattr(ServiceEnumAgent, "run", fake_service_enum_run)
    monkeypatch.setattr(VulnScanAgent, "run", fake_vuln_scan_run)
    monkeypatch.setattr(WebAppAgent, "run", fake_webapp_run)

    scope_record = _scope_record(
        allowed_categories=[TestCategory.SERVICE_ENUM, TestCategory.VULN_SCAN, TestCategory.WEBAPP_TEST]
    )
    state = _base_state(scope_record, target_service={"target": "10.0.0.5", "port": 80, "service": "http"})

    result = await scan_graph.test_service_node(state)
    categories = {f["category"] for f in result["service_findings"]}

    assert categories == {"service_enum", "vuln_scan", "webapp_test"}
    assert all(f["error"] is None for f in result["service_findings"])


async def test_test_service_node_isolates_a_failing_category(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    async def failing_run(self, executor, target, port, service):
        raise RuntimeError("nmap not found")

    async def ok_run(self, executor, target, port, service):
        return []

    monkeypatch.setattr(ServiceEnumAgent, "run", failing_run)
    monkeypatch.setattr(VulnScanAgent, "run", ok_run)

    scope_record = _scope_record(allowed_categories=[TestCategory.SERVICE_ENUM, TestCategory.VULN_SCAN])
    state = _base_state(scope_record, target_service={"target": "10.0.0.5", "port": 22, "service": "ssh"})

    result = await scan_graph.test_service_node(state)
    by_category = {f["category"]: f for f in result["service_findings"]}

    assert by_category["service_enum"]["error"] == "nmap not found"
    assert by_category["vuln_scan"]["error"] is None


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
