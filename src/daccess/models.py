"""Shared data model for the governed data access platform."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Sensitivity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    RESTRICTED = "restricted"


class RequestStatus(str, Enum):
    REQUESTED = "requested"
    APPROVED = "approved"
    DENIED = "denied"
    ACTIVE = "active"          # grant issued and usable
    EXPIRED = "expired"
    REVOKED = "revoked"


class Masking(str, Enum):
    NONE = "none"
    PARTIAL = "partial"        # show first/last few characters, mask the rest
    FULL = "full"              # replace the whole value
    HASH = "hash"              # deterministic salted hash (joinable, not reversible)
    REDACT = "redact"          # drop the column entirely from results


@dataclass
class ColumnPolicy:
    column: str
    masking: Masking = Masking.NONE
    forbidden: bool = False    # never visible to this grantee, even masked


@dataclass
class Dataset:
    name: str
    columns: list[str]
    classification: Sensitivity = Sensitivity.MEDIUM
    owner: str = "data-platform"
    rows: list[dict[str, Any]] = field(default_factory=list)

    def filtered_rows(self, row_filter: dict[str, Any]) -> list[dict[str, Any]]:
        if not row_filter:
            return list(self.rows)
        return [
            r for r in self.rows
            if all(r.get(k) == v for k, v in row_filter.items())
        ]


@dataclass
class AccessRequest:
    """A request for access to a dataset, for a declared purpose.

    Lifecycle: requested -> approved (by the required approvers) -> active
    (grant issued) -> expired / revoked. A request that fails any policy
    check is denied, never silently downgraded.
    """
    request_id: str
    dataset: str
    requester: str
    requester_role: str
    purpose: str
    columns: list[str]
    column_policies: dict[str, ColumnPolicy] = field(default_factory=dict)
    row_filter: dict[str, Any] = field(default_factory=dict)
    sensitivity: Sensitivity = Sensitivity.MEDIUM
    expires_at: datetime | None = None
    status: RequestStatus = RequestStatus.REQUESTED
    created_at: datetime | None = None
    approvals: list[str] = field(default_factory=list)
    denial_reason: str | None = None
    row_budget: int = 100_000
    query_budget: int = 1_000

    def policy_for(self, column: str) -> ColumnPolicy:
        return self.column_policies.get(column, ColumnPolicy(column=column))

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def is_usable(self, now: datetime) -> bool:
        return self.status == RequestStatus.ACTIVE and not self.is_expired(now)


@dataclass
class Grant:
    """A purpose-scoped, expiring grant issued from an approved request."""
    grant_id: str
    request_id: str
    dataset: str
    grantee: str
    grantee_role: str
    purpose: str
    columns: list[str]
    column_policies: dict[str, ColumnPolicy] = field(default_factory=dict)
    row_filter: dict[str, Any] = field(default_factory=dict)
    sensitivity: Sensitivity = Sensitivity.MEDIUM
    expires_at: datetime | None = None
    active: bool = True
    row_budget: int = 100_000
    query_budget: int = 1_000
    created_at: datetime | None = None

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at

    def is_usable(self, now: datetime) -> bool:
        return self.active and not self.is_expired(now)


@dataclass
class DerivedExtract:
    """A downstream extract derived from a grant; revocation propagates here."""
    extract_id: str
    grant_id: str
    description: str
    active: bool = True
    revoked_reason: str | None = None


@dataclass
class QueryRequest:
    grant_id: str
    columns: list[str]
    row_filter: dict[str, Any] = field(default_factory=dict)
    limit: int = 100
    grantee: str = ""


@dataclass
class QueryResult:
    grant_id: str
    rows: list[dict[str, Any]]
    rows_scanned: int
    rows_returned: int
    columns_masked: list[str]


@dataclass
class Recertification:
    """An access review: the dataset owner must re-confirm a grant or it lapses."""
    review_id: str
    grant_id: str
    reviewer: str
    due_at: datetime
    decision: str | None = None          # "confirmed" | "revoked"
    decided_at: datetime | None = None


class AccessError(ValueError):
    """Fail-closed error: the requested access operation is not permitted."""


class BudgetExceeded(AccessError):
    pass


class PolicyViolation(AccessError):
    pass
