"""Access-request lifecycle: request -> approve (with separation of duties)
-> grant issued -> expired / revoked.

Approval rules, enforced fail-closed:
- the requester may never approve their own request;
- HIGH and RESTRICTED data need two distinct approvers;
- approvers must hold a role allowed to approve that classification;
- a grant is issued only once all required approvals are recorded.
"""
from __future__ import annotations

from datetime import datetime

from daccess.audit import AuditLog
from daccess.catalog import check_request_policy, may_approve, required_approvals
from daccess.models import (
    AccessError,
    AccessRequest,
    Dataset,
    Grant,
    PolicyViolation,
    RequestStatus,
)


class RequestStore:
    def __init__(self, audit: AuditLog | None = None):
        self.requests: dict[str, AccessRequest] = {}
        self.audit = audit

    def submit(self, request: AccessRequest, dataset: Dataset,
               now: datetime) -> AccessRequest:
        if request.request_id in self.requests:
            raise AccessError(f"request {request.request_id!r} already exists")
        check_request_policy(request, dataset)
        if request.expires_at is not None and request.expires_at <= now:
            raise PolicyViolation("expiry must be in the future")
        request.created_at = now
        request.status = RequestStatus.REQUESTED
        self.requests[request.request_id] = request
        if self.audit:
            self.audit.append("request.submitted", request.requester,
                              request.request_id,
                              {"dataset": request.dataset, "purpose": request.purpose,
                               "sensitivity": request.sensitivity.value})
        return request

    def get(self, request_id: str) -> AccessRequest:
        try:
            return self.requests[request_id]
        except KeyError:
            raise AccessError(f"unknown request {request_id!r}") from None

    def list(self) -> list[AccessRequest]:
        return list(self.requests.values())

    def approve(self, request_id: str, approver: str, approver_role: str,
                now: datetime) -> AccessRequest:
        request = self.get(request_id)
        if request.status != RequestStatus.REQUESTED:
            raise AccessError(
                f"cannot approve request in status {request.status.value}")
        if approver == request.requester:
            raise PolicyViolation("requester may not approve their own request")
        if approver in request.approvals:
            raise PolicyViolation(f"{approver!r} has already approved this request")
        if not may_approve(request.sensitivity, approver_role):
            raise PolicyViolation(
                f"role {approver_role!r} may not approve "
                f"{request.sensitivity.value}-sensitivity access")
        request.approvals.append(approver)
        needed = required_approvals(request.sensitivity)
        if len(request.approvals) < needed:
            if self.audit:
                self.audit.append("request.approved_partial", approver, request_id,
                                  {"approvals": len(request.approvals),
                                   "required": needed})
            return request
        request.status = RequestStatus.APPROVED
        if self.audit:
            self.audit.append("request.approved", approver, request_id,
                              {"approvals": list(request.approvals)})
        return request

    def deny(self, request_id: str, approver: str, reason: str) -> AccessRequest:
        request = self.get(request_id)
        if request.status != RequestStatus.REQUESTED:
            raise AccessError(
                f"cannot deny request in status {request.status.value}")
        if not reason.strip():
            raise AccessError("denial requires a reason")
        request.status = RequestStatus.DENIED
        request.denial_reason = reason
        if self.audit:
            self.audit.append("request.denied", approver, request_id,
                              {"reason": reason})
        return request

    def issue_grant(self, request_id: str, now: datetime) -> Grant:
        request = self.get(request_id)
        if request.status != RequestStatus.APPROVED:
            raise AccessError(
                f"grant requires an approved request, not {request.status.value}")
        grant = Grant(
            grant_id=f"grant-{request.request_id}",
            request_id=request.request_id,
            dataset=request.dataset,
            grantee=request.requester,
            grantee_role=request.requester_role,
            purpose=request.purpose,
            columns=list(request.columns),
            column_policies=dict(request.column_policies),
            row_filter=dict(request.row_filter),
            sensitivity=request.sensitivity,
            expires_at=request.expires_at,
            row_budget=request.row_budget,
            query_budget=request.query_budget,
            created_at=now,
        )
        request.status = RequestStatus.ACTIVE
        if self.audit:
            self.audit.append("grant.issued", "system", grant.grant_id,
                              {"request_id": request_id, "grantee": grant.grantee,
                               "expires_at": grant.expires_at.isoformat()
                               if grant.expires_at else None})
        return grant
