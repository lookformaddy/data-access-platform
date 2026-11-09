"""Lifecycle tests: expiry, revocation propagation, recertification,
and compliance reporting."""
from datetime import timedelta

import pytest

from conftest import NOW
from daccess.lifecycle import (
    compliance_report,
    decide_recertification,
    expire_grants,
    open_recertification,
    revoke_grant,
)
from daccess.models import AccessError, DerivedExtract, Recertification, RequestStatus


def test_expire_grants_marks_expired(approved_grant, store):
    grant, request = approved_grant
    expired = expire_grants([grant], store.list(), NOW + timedelta(days=91))
    assert expired == [grant]
    assert not grant.active
    assert request.status == RequestStatus.EXPIRED


def test_revoke_propagates_only_to_own_extracts(approved_grant, audit):
    grant, _ = approved_grant
    extracts = [DerivedExtract("ext-1", grant.grant_id, "training snapshot"),
                DerivedExtract("ext-2", "grant-other", "unrelated")]
    propagated = revoke_grant(grant, "data-platform", "purpose ended",
                              extracts, audit)
    assert propagated == [extracts[0]]
    assert not extracts[0].active
    assert extracts[1].active
    assert not grant.active


def test_revoke_requires_reason_and_is_idempotent_guard(approved_grant):
    grant, _ = approved_grant
    with pytest.raises(AccessError):
        revoke_grant(grant, "data-platform", "   ")
    revoke_grant(grant, "data-platform", "purpose ended")
    with pytest.raises(AccessError):
        revoke_grant(grant, "data-platform", "again")


def test_recertification_confirm_keeps_grant(approved_grant, audit):
    grant, _ = approved_grant
    review = open_recertification(grant, "data-platform", 30, NOW, audit)
    decide_recertification(review, grant, "confirmed", NOW, audit=audit)
    assert review.decision == "confirmed"
    assert grant.active


def test_recertification_revoke_kills_grant_and_extracts(approved_grant, audit):
    grant, _ = approved_grant
    extracts = [DerivedExtract("ext-1", grant.grant_id, "snapshot")]
    review = open_recertification(grant, "data-platform", 30, NOW, audit)
    decide_recertification(review, grant, "revoked", NOW, extracts, audit)
    assert not grant.active
    assert not extracts[0].active


def test_recertification_cannot_be_decided_twice(approved_grant):
    grant, _ = approved_grant
    review = open_recertification(grant, "data-platform", 30, NOW)
    decide_recertification(review, grant, "confirmed", NOW)
    with pytest.raises(AccessError):
        decide_recertification(review, grant, "confirmed", NOW)


def test_compliance_report_flags_expired_but_active(approved_grant, store):
    grant, _ = approved_grant
    review = Recertification(review_id="review-1", grant_id=grant.grant_id,
                             reviewer="data-platform",
                             due_at=NOW - timedelta(days=1))
    report = compliance_report([grant], store.list(), [review],
                               NOW + timedelta(days=91))
    assert report["total_grants"] == 1
    assert report["active_grants"] == 1
    assert report["by_sensitivity"] == {"high": 1}
    assert report["expired_but_active"] == [grant.grant_id]
    assert report["overdue_reviews"] == ["review-1"]
    assert report["pending_requests"] == 0
