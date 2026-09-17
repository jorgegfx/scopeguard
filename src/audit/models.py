"""Typed audit event records. Every command and result gets one of these."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AuditEvent(BaseModel):
    run_id: str
    branch_id: str | None = None
    timestamp: datetime
    event_type: str  # "authorization_decision" | "command_executed" | "result" | "error"
    payload: dict[str, Any]
