import sys
from datetime import datetime, timedelta, timezone

import pytest

from audit.log import AuditLogger
from scope.checker import ScopeViolation
from scope.models import AuthorizationArtifact, ScopeRecord, ScopeTarget, TestCategory, TimeWindow
from tools.base import ToolExecutor


def _scope_record(**overrides) -> ScopeRecord:
    now = datetime.now(timezone.utc)
    defaults = dict(
        run_id="tool-test-run",
        targets=[ScopeTarget(value="10.0.0.5")],
        authorization=AuthorizationArtifact(kind="self_attestation", reference_id="t"),
        time_window=TimeWindow(starts_at=now - timedelta(hours=1), ends_at=now + timedelta(hours=1)),
        allowed_categories=[TestCategory.PORT_SCAN],
    )
    defaults.update(overrides)
    return ScopeRecord(**defaults)


async def test_run_executes_command_and_returns_stdout(tmp_path):
    scope_record = _scope_record()
    executor = ToolExecutor(scope_record, AuditLogger(run_id=scope_record.run_id, log_dir=tmp_path))

    result = await executor.run(
        target="10.0.0.5",
        category=TestCategory.PORT_SCAN,
        command=[sys.executable, "-c", "print('hello')"],
    )

    assert result.returncode == 0
    assert "hello" in result.stdout


async def test_run_refuses_and_never_executes_out_of_scope_target(tmp_path):
    scope_record = _scope_record()
    executor = ToolExecutor(scope_record, AuditLogger(run_id=scope_record.run_id, log_dir=tmp_path))

    with pytest.raises(ScopeViolation):
        await executor.run(
            target="10.0.0.99",
            category=TestCategory.PORT_SCAN,
            command=[sys.executable, "-c", "print('should never run')"],
        )
