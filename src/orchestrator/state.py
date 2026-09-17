"""Shared LangGraph state for a scan run."""

from __future__ import annotations

import operator
from asyncio import Semaphore
from enum import Enum
from typing import Annotated, NotRequired, TypedDict

from pydantic import BaseModel

from scope.models import ScopeRecord
from tools.rate_limit import RateLimiter


class ServiceTarget(TypedDict):
    target: str
    port: int
    service: str | None


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Finding(BaseModel):
    title: str
    severity: Severity
    description: str
    evidence: str | None = None
    cve_ids: list[str] = []


class ServiceFinding(TypedDict):
    target: str
    port: int
    category: str
    findings: list[Finding]
    error: str | None


class RunState(TypedDict):
    run_id: str
    scope_record: ScopeRecord
    discovered_services: list[ServiceTarget]
    # operator.add reducer: LangGraph merges each parallel branch's partial
    # result into this list rather than branches overwriting one another.
    service_findings: Annotated[list[ServiceFinding], operator.add]
    report: str | None
    # Profile-derived, shared across every ToolExecutor in the run so the
    # scan profile's concurrency cap and rate limit are actually enforced.
    tool_semaphore: Semaphore
    rate_limiter: RateLimiter
    # Only present on a Send-spawned test_service branch.
    target_service: NotRequired[ServiceTarget]
