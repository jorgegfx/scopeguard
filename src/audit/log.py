"""Append-only audit log, safe under concurrent writers.

v1 writes newline-delimited JSON through a lock so every branch's writes
are serialized without corrupting the file. If this becomes a bottleneck
under heavy fan-out, route writes through one dedicated writer task/queue
instead of widening the lock, and consider sqlite (WAL mode) if queryability
matters more than simplicity.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

from audit.models import AuditEvent

if TYPE_CHECKING:
    from scope.checker import AuthorizationDecision


class AuditLogger:
    def __init__(self, run_id: str, log_dir: str | Path = "audit_logs"):
        self.run_id = run_id
        self._path = Path(log_dir) / f"{run_id}.jsonl"
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def log_event(self, event_type: str, payload: dict[str, Any], branch_id: str | None = None) -> None:
        event = AuditEvent(
            run_id=self.run_id,
            branch_id=branch_id,
            timestamp=datetime.now(timezone.utc),
            event_type=event_type,
            payload=payload,
        )
        line = event.model_dump_json()
        with self._lock, self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")

    def log_authorization_decision(self, decision: "AuthorizationDecision") -> None:
        self.log_event(
            "authorization_decision",
            {
                "allowed": decision.allowed,
                "target": decision.target,
                "category": decision.category.value,
                "reason": decision.reason,
            },
        )


def read_events(
    run_id: str, log_dir: str | Path = "audit_logs", event_type: str | None = None
) -> list[AuditEvent]:
    """Read back a run's audit events (optionally filtered by event_type).

    Read-only: it never mutates the append-only log. Lines that fail to parse
    are skipped rather than aborting -- a report should still render from a
    partially-written or truncated log (e.g. a crashed run) rather than fail
    closed on a reporting path, where fail-closed buys no safety.
    """
    path = Path(log_dir) / f"{run_id}.jsonl"
    if not path.exists():
        return []
    events: list[AuditEvent] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = AuditEvent.model_validate_json(line)
        except ValueError:
            continue
        if event_type is None or event.event_type == event_type:
            events.append(event)
    return events
