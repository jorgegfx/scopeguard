from datetime import datetime, timedelta, timezone

import pytest

from audit.log import AuditLogger
from scope.checker import ScopeViolation, authorize
from scope.models import (
    AuthorizationArtifact,
    ScopeRecord,
    ScopeTarget,
    TestCategory,
    TimeWindow,
)


def _scope_record(**overrides) -> ScopeRecord:
    now = datetime.now(timezone.utc)
    defaults = dict(
        run_id="test-run",
        targets=[ScopeTarget(value="10.0.0.0/24")],
        authorization=AuthorizationArtifact(kind="self_attestation", reference_id="test-1"),
        time_window=TimeWindow(starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1)),
        allowed_categories=[TestCategory.PASSIVE_RECON, TestCategory.PORT_SCAN],
    )
    defaults.update(overrides)
    return ScopeRecord(**defaults)


@pytest.fixture
def audit_logger(tmp_path):
    return AuditLogger(run_id="test-run", log_dir=tmp_path)


def test_allows_in_scope_target_and_authorized_category(audit_logger):
    record = _scope_record()
    decision = authorize(record, "10.0.0.5", TestCategory.PORT_SCAN, audit_logger)
    assert decision.allowed


def test_refuses_target_outside_scope(audit_logger):
    record = _scope_record()
    with pytest.raises(ScopeViolation):
        authorize(record, "10.0.1.5", TestCategory.PORT_SCAN, audit_logger)


def test_refuses_unauthorized_category(audit_logger):
    record = _scope_record()
    with pytest.raises(ScopeViolation):
        authorize(record, "10.0.0.5", TestCategory.VULN_SCAN, audit_logger)


def test_refuses_outside_time_window(audit_logger):
    now = datetime.now(timezone.utc)
    record = _scope_record(
        time_window=TimeWindow(
            starts_at=now - timedelta(hours=3),
            ends_at=now - timedelta(hours=1),
        )
    )
    with pytest.raises(ScopeViolation):
        authorize(record, "10.0.0.5", TestCategory.PORT_SCAN, audit_logger)


def test_hostname_target_matches_exactly(audit_logger):
    record = _scope_record(targets=[ScopeTarget(value="scan-target.example.com")])
    decision = authorize(record, "scan-target.example.com", TestCategory.PORT_SCAN, audit_logger)
    assert decision.allowed


def test_every_decision_is_logged(audit_logger, tmp_path):
    record = _scope_record()
    with pytest.raises(ScopeViolation):
        authorize(record, "10.0.1.5", TestCategory.PORT_SCAN, audit_logger)

    log_lines = (tmp_path / "test-run.jsonl").read_text().strip().splitlines()
    assert len(log_lines) == 1
    assert "not in scope record" in log_lines[0]
