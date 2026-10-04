from datetime import datetime, timedelta, timezone

from agents.report.render import (
    ToolInvocation,
    render_markdown,
    render_pdf,
    summarize_tool_usage,
)
from audit.models import AuditEvent
from orchestrator.state import Finding, Severity
from scope.models import AuthorizationArtifact, ScopeRecord, ScopeTarget, TestCategory, TimeWindow


def _command_event(command: list[str], target: str) -> AuditEvent:
    return AuditEvent(
        run_id="report-test-run",
        timestamp=datetime.now(timezone.utc),
        event_type="command_executed",
        payload={"command": command, "target": target},
    )


def _tool_invocations() -> list[ToolInvocation]:
    return summarize_tool_usage(
        [
            _command_event(["/usr/bin/nmap", "-sV", "-p-", "10.0.0.5"], "10.0.0.5"),
            _command_event(["/usr/bin/nmap", "-sV", "-p-", "10.0.0.5"], "10.0.0.5"),
            _command_event(["curl", "-sI", "http://10.0.0.5"], "10.0.0.5"),
        ]
    )


def _scope_record() -> ScopeRecord:
    now = datetime.now(timezone.utc)
    return ScopeRecord(
        run_id="report-test-run",
        targets=[ScopeTarget(value="10.0.0.0/24")],
        authorization=AuthorizationArtifact(kind="self_attestation", reference_id="test-1"),
        time_window=TimeWindow(starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1)),
        allowed_categories=[TestCategory.PORT_SCAN, TestCategory.VULN_SCAN],
    )


def _service_findings():
    return [
        {
            "target": "10.0.0.5",
            "port": 443,
            "category": "vuln_scan",
            "findings": [
                Finding(
                    title="Outdated TLS library",
                    severity=Severity.HIGH,
                    description="Server reports a TLS library version with a known CVE.",
                    evidence="X-Powered-By: OpenSSL/1.0.1",
                    cve_ids=["CVE-2014-0160"],
                ),
            ],
            "error": None,
        },
        {
            "target": "10.0.0.9",
            "port": 22,
            "category": "service_enum",
            "findings": [],
            "error": "connection timed out",
        },
    ]


def test_render_markdown_includes_findings_and_failures():
    md = render_markdown("run-uuid-123", _scope_record(), _service_findings())

    assert "run-uuid-123" in md
    assert "HIGH severity" in md
    assert "Outdated TLS library" in md
    assert "CVE-2014-0160" in md
    assert "Test failures" in md
    assert "connection timed out" in md


def test_render_pdf_writes_nonempty_file(tmp_path):
    output_path = render_pdf("run-uuid-123", _scope_record(), _service_findings(), tmp_path / "report.pdf")

    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_summarize_tool_usage_collapses_duplicates_and_ignores_non_commands():
    events = [
        _command_event(["/usr/bin/nmap", "-sV", "10.0.0.5"], "10.0.0.5"),
        _command_event(["/usr/bin/nmap", "-sV", "10.0.0.5"], "10.0.0.5"),
        AuditEvent(
            run_id="r", timestamp=datetime.now(timezone.utc), event_type="result", payload={"command": ["x"]}
        ),
    ]
    invocations = summarize_tool_usage(events)

    assert len(invocations) == 1
    inv = invocations[0]
    assert inv.tool == "nmap"  # binary path reduced to its name
    assert inv.parameters == "-sV 10.0.0.5"
    assert inv.count == 2


def test_render_markdown_includes_tools_used_section():
    md = render_markdown("run-uuid-123", _scope_record(), _service_findings(), _tool_invocations())

    assert "Tools used" in md
    assert "nmap" in md
    assert "`-sV -p- 10.0.0.5`" in md  # parameters rendered
    assert "| 2 |" in md  # duplicate nmap runs collapsed to a count
    assert "curl" in md


def test_render_markdown_omits_tools_section_when_none():
    md = render_markdown("run-uuid-123", _scope_record(), _service_findings())

    assert "Tools used" not in md


def test_render_pdf_with_tool_invocations_writes_nonempty_file(tmp_path):
    output_path = render_pdf(
        "run-uuid-123", _scope_record(), _service_findings(), tmp_path / "report.pdf", _tool_invocations()
    )

    assert output_path.exists()
    assert output_path.stat().st_size > 0
