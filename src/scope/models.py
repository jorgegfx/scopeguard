"""Scope record schema: the single source of truth for what a run is authorized to touch."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, field_validator


class TestCategory(str, Enum):
    PASSIVE_RECON = "passive_recon"
    PORT_SCAN = "port_scan"
    SERVICE_ENUM = "service_enum"
    VULN_SCAN = "vuln_scan"
    WEBAPP_TEST = "webapp_test"


class AuthorizationArtifact(BaseModel):
    """Proof that the user is authorized to test the declared targets."""

    kind: str  # "engagement_letter" | "self_attestation" | "signed_statement"
    reference_id: str
    attested_by: str | None = None
    notes: str | None = None


class TimeWindow(BaseModel):
    starts_at: datetime
    ends_at: datetime

    @field_validator("ends_at")
    @classmethod
    def _ends_after_starts(cls, v: datetime, info) -> datetime:
        starts_at = info.data.get("starts_at")
        if starts_at is not None and v <= starts_at:
            raise ValueError("ends_at must be after starts_at")
        return v

    def contains(self, when: datetime) -> bool:
        return self.starts_at <= when <= self.ends_at


class ScopeTarget(BaseModel):
    """A single target expression: CIDR, single IP, or hostname."""

    value: str

    def matches(self, candidate: str) -> bool:
        try:
            network = ipaddress.ip_network(self.value, strict=False)
            address = ipaddress.ip_address(candidate)
            return address in network
        except ValueError:
            return candidate.lower() == self.value.lower()


class ScopeRecord(BaseModel):
    """A run's full authorization envelope. Immutable once a run starts."""

    run_id: str
    targets: list[ScopeTarget]
    authorization: AuthorizationArtifact
    time_window: TimeWindow
    allowed_categories: list[TestCategory]

    def target_in_scope(self, candidate: str) -> bool:
        return any(t.matches(candidate) for t in self.targets)

    def category_allowed(self, category: TestCategory) -> bool:
        return category in self.allowed_categories
