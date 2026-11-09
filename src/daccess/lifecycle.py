"""Grant lifecycle: expiry sweeps, revocation with downstream propagation,
access reviews (recertification), and compliance reporting."""
from __future__ import annotations

from datetime import datetime, timedelta

from daccess.audit import AuditLog
from daccess.models import (
    AccessError,
    DerivedExtract,
    Grant,
    Recertification,
    RequestStatus,
    Sensitivity,
)


def expire_grants(grants: list[Grant], requests: list | None, now: datetime,
                  audit: AuditLog | None = None) -> list[Grant]:
    """Mark past-due grants expired (and their requests too)."""
    expired = []
    request_by_id = {r.request_id: r for r in (requests or [])}
    for grant in grants:
        if grant.active and grant.is_expired(now):
            grant.active = False
            expired.append(grant)
            request = request_by_id.get(grant.request_id)
            if request is not None and request.status == RequestStatus.ACTIVE:
                request.status = RequestStatus.EXPIRED
            if audit:
                audit.append("grant.expired", "system", grant.grant_id,
                             {"dataset": grant.dataset, "grantee": grant.grantee})
    return expired


def revoke_grant(grant: Grant, actor: str, reason: str,
                 extracts: list[DerivedExtract] | None = None,
                 audit: AuditLog | None = None) -> list[DerivedExtract]:
    """Revoke a grant and propagate to every derived extract of that grant."""
    if not grant.active:
        raise AccessError(f"grant {grant.grant_id!r} is already inactive")
    if not reason.strip():
        raise AccessError("revocation requires a reason")
    grant.active = False
    propagated: list[DerivedExtract] = []
    for extract in extracts or []:
        if extract.grant_id == grant.grant_id and extract.active:
            extract.active = False
            extract.revoked_reason = f"parent grant revoked: {reason}"
            propagated.append(extract)
    if audit:
        audit.append("grant.revoked", actor, grant.grant_id,
                     {"reason": reason, "extracts_revoked": len(propagated)})
    return propagated


def open_recertification(grant: Grant, reviewer: str, due_in_days: int,
                         now: datetime, audit: AuditLog | None = None) -> Recertification:
    if not grant.active:
        raise AccessError("cannot open a review for an inactive grant")
    review = Recertification(
        review_id=f"review-{grant.grant_id}",
        grant_id=grant.grant_id,
        reviewer=reviewer,
        due_at=now + timedelta(days=due_in_days),
    )
    if audit:
        audit.append("recertification.opened", reviewer, grant.grant_id,
                     {"review_id": review.review_id,
                      "due_at": review.due_at.isoformat()})
    return review


def decide_recertification(review: Recertification, grant: Grant, decision: str,
                           now: datetime, extracts: list[DerivedExtract] | None = None,
                           audit: AuditLog | None = None) -> Recertification:
    """Confirm keeps the grant; any other decision revokes it (and propagates)."""
    if review.decision is not None:
        raise AccessError(f"review {review.review_id!r} already decided")
    if decision not in ("confirmed", "revoked"):
        raise AccessError("decision must be 'confirmed' or 'revoked'")
    review.decision = decision
    review.decided_at = now
    if decision == "revoked":
        if grant.active:
            revoke_grant(grant, review.reviewer,
                         f"recertification {review.review_id} revoked access",
                         extracts, audit)
    if audit:
        audit.append("recertification.decided", review.reviewer, grant.grant_id,
                     {"review_id": review.review_id, "decision": decision})
    return review


def compliance_report(grants: list[Grant], requests: list,
                      reviews: list[Recertification], now: datetime) -> dict:
    by_sensitivity: dict[str, int] = {}
    for grant in grants:
        by_sensitivity[grant.sensitivity.value] = \
            by_sensitivity.get(grant.sensitivity.value, 0) + 1
    expired_but_active = [g.grant_id for g in grants
                          if g.active and g.is_expired(now)]
    overdue_reviews = [r.review_id for r in reviews
                       if r.decision is None and now > r.due_at]
    return {
        "total_grants": len(grants),
        "active_grants": sum(1 for g in grants if g.active),
        "by_sensitivity": by_sensitivity,
        "by_request_status": {s.value: sum(1 for r in requests if r.status == s)
                              for s in RequestStatus},
        "expired_but_active": expired_but_active,
        "overdue_reviews": overdue_reviews,
        "pending_requests": sum(1 for r in requests
                                if r.status == RequestStatus.REQUESTED),
        "generated_at": now.isoformat(),
    }
