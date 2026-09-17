"""The single gate every tool-executing function must pass through.

No sub-agent may call nmap, curl, or any other OS-level tool without first
going through authorize(). This module has no knowledge of *how* to run a
tool -- only whether it's allowed to, against the given scope record.

Fails closed: any ambiguity (target not listed, category not enabled,
outside the time window) is a refusal, not a best-effort guess. Every
decision -- allow or deny -- is written to the audit log before this
function returns.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from audit.log import AuditLogger
from scope.models import ScopeRecord, TestCategory

logger = logging.getLogger(__name__)


class ScopeViolation(Exception):
    """Raised when a tool call is refused. Always logged before being raised."""


@dataclass
class AuthorizationDecision:
    allowed: bool
    scope_record_run_id: str
    target: str
    category: TestCategory
    reason: str


def authorize(
    scope_record: ScopeRecord,
    target: str,
    category: TestCategory,
    audit_logger: AuditLogger,
    now: datetime | None = None,
) -> AuthorizationDecision:
    now = now or datetime.now(timezone.utc)

    if not scope_record.time_window.contains(now):
        decision = AuthorizationDecision(
            allowed=False,
            scope_record_run_id=scope_record.run_id,
            target=target,
            category=category,
            reason="outside authorized time window",
        )
    elif not scope_record.target_in_scope(target):
        decision = AuthorizationDecision(
            allowed=False,
            scope_record_run_id=scope_record.run_id,
            target=target,
            category=category,
            reason="target not in scope record",
        )
    elif not scope_record.category_allowed(category):
        decision = AuthorizationDecision(
            allowed=False,
            scope_record_run_id=scope_record.run_id,
            target=target,
            category=category,
            reason="test category not authorized for this run",
        )
    else:
        decision = AuthorizationDecision(
            allowed=True,
            scope_record_run_id=scope_record.run_id,
            target=target,
            category=category,
            reason="authorized",
        )

    audit_logger.log_authorization_decision(decision)

    if not decision.allowed:
        message = (
            f"refused: target={target!r} category={category.value!r} "
            f"run={scope_record.run_id!r} reason={decision.reason!r}"
        )
        # "refuses (loudly, logged)" per CLAUDE.md -- a denial written only
        # to the audit JSONL is easy to miss while a scan is running.
        logger.warning(message)
        raise ScopeViolation(message)

    logger.debug("authorized: target=%r category=%r", target, category.value)
    return decision
