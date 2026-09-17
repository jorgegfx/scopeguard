from datetime import datetime, timedelta, timezone

from agents.report.render import render_markdown, render_pdf
from orchestrator.state import Finding, Severity
from scope.models import AuthorizationArtifact, ScopeRecord, ScopeTarget, TestCategory, TimeWindow


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
