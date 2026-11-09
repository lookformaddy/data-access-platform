"""Access-request lifecycle tests: submission, approvals with separation
of duties, denial, and grant issuance."""
from datetime import timedelta

import pytest

from conftest import NOW, make_request
from daccess.models import AccessError, RequestStatus


def test_submit_and_approve_two_stewards(store, dataset):
    request = make_request()
    store.submit(request, dataset, NOW)
    assert request.status == RequestStatus.REQUESTED
    store.approve(request.request_id, "steward-a", "data-steward", NOW)
    # One approval is not enough for HIGH data.
    assert request.status == RequestStatus.REQUESTED
    store.approve(request.request_id, "steward-b", "data-steward", NOW)
    assert request.status == RequestStatus.APPROVED
    assert request.approvals == ["steward-a", "steward-b"]


def test_low_sensitivity_needs_one_approver(store, dataset):
    from daccess.models import Sensitivity
    dataset.classification = Sensitivity.LOW
    request = make_request(sensitivity=Sensitivity.LOW, purpose="customer-support")
    store.submit(request, dataset, NOW)
    store.approve(request.request_id, "steward-a", "data-steward", NOW)
    assert request.status == RequestStatus.APPROVED


def test_requester_cannot_self_approve(store, dataset):
    request = make_request()
    store.submit(request, dataset, NOW)
    with pytest.raises(AccessError):
        store.approve(request.request_id, "analyst-1", "data-steward", NOW)


def test_same_approver_twice_rejected(store, dataset):
    request = make_request()
    store.submit(request, dataset, NOW)
    store.approve(request.request_id, "steward-a", "data-steward", NOW)
    with pytest.raises(AccessError):
        store.approve(request.request_id, "steward-a", "data-steward", NOW)


def test_wrong_role_cannot_approve(store, dataset):
    request = make_request()
    store.submit(request, dataset, NOW)
    with pytest.raises(AccessError):
        store.approve(request.request_id, "analyst-2", "analyst", NOW)


def test_duplicate_request_rejected(store, dataset):
    store.submit(make_request(), dataset, NOW)
    with pytest.raises(AccessError):
        store.submit(make_request(), dataset, NOW)


def test_past_expiry_rejected(store, dataset):
    request = make_request(expires_at=NOW - timedelta(days=1))
    with pytest.raises(AccessError):
        store.submit(request, dataset, NOW)


def test_deny_requires_reason_and_blocks_grant(store, dataset):
    request = make_request()
    store.submit(request, dataset, NOW)
    with pytest.raises(AccessError):
        store.deny(request.request_id, "steward-a", "   ")
    store.deny(request.request_id, "steward-a", "purpose too broad")
    assert request.status == RequestStatus.DENIED
    assert request.denial_reason == "purpose too broad"
    with pytest.raises(AccessError):
        store.issue_grant(request.request_id, NOW)


def test_grant_issued_only_after_full_approval(store, dataset):
    request = make_request()
    store.submit(request, dataset, NOW)
    with pytest.raises(AccessError):
        store.issue_grant(request.request_id, NOW)
    store.approve(request.request_id, "steward-a", "data-steward", NOW)
    with pytest.raises(AccessError):
        store.issue_grant(request.request_id, NOW)
    store.approve(request.request_id, "steward-b", "data-steward", NOW)
    grant = store.issue_grant(request.request_id, NOW)
    assert grant.grant_id == "grant-req-1"
    assert grant.grantee == "analyst-1"
    assert grant.columns == request.columns
    assert request.status == RequestStatus.ACTIVE


def test_unknown_request_rejected(store):
    with pytest.raises(AccessError):
        store.get("no-such-request")
