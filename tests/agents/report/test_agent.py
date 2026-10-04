from datetime import datetime, timedelta, timezone

import pytest

from agents.report.agent import ReportAgent
from audit.log import AuditLogger
from scope.models import AuthorizationArtifact, ScopeRecord, ScopeTarget, TestCategory, TimeWindow


def _scope_record() -> ScopeRecord:
    now = datetime.now(timezone.utc)
    return ScopeRecord(
        run_id="report-agent-test",
        targets=[ScopeTarget(value="10.0.0.0/24")],
        authorization=AuthorizationArtifact(kind="self_attestation", reference_id="test-1"),
        time_window=TimeWindow(starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1)),
        allowed_categories=[TestCategory.PORT_SCAN],
    )


@pytest.mark.asyncio
async def test_report_agent_includes_tools_from_audit_log(tmp_path):
    run_id = "run-abc"
    audit_dir = tmp_path / "audit_logs"
    logger = AuditLogger(run_id=run_id, log_dir=audit_dir)
    logger.log_event("command_executed", {"command": ["nmap", "-sV", "-p-", "10.0.0.5"], "target": "10.0.0.5"})
    logger.log_event("result", {"command": ["nmap"], "returncode": 0})

    service_findings = [{"target": "10.0.0.5", "port": 443, "category": "port_scan", "findings": [], "error": None}]

    agent = ReportAgent(agent_name="report")
    paths = await agent.run(
        run_id,
        _scope_record(),
        service_findings,
        output_dir=tmp_path / "reports",
        audit_log_dir=audit_dir,
    )

    md = paths.markdown_path.read_text(encoding="utf-8")
    assert "Tools used" in md
    assert "nmap" in md
    assert "`-sV -p- 10.0.0.5`" in md
    assert paths.pdf_path.exists() and paths.pdf_path.stat().st_size > 0
