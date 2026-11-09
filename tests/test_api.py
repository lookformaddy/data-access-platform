"""FastAPI tests. These run in the venv (FastAPI installed); on a plain
system python without FastAPI they skip, per the project conventions."""
import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from daccess.service import app  # noqa: E402

client = TestClient(app)

REQUEST = {
    "request_id": "api-req-1", "dataset": "customers", "requester": "analyst-1",
    "requester_role": "analyst", "purpose": "model-training",
    "columns": ["customer_id", "email", "region", "lifetime_value"],
    "column_policies": [
        {"column": "email", "masking": "hash"},
        {"column": "customer_id", "masking": "partial"}],
    "sensitivity": "high",
    "expires_at": "2030-01-01T00:00:00Z",
    "row_budget": 10_000, "query_budget": 100,
}


def test_full_flow_request_approve_grant_query():
    resp = client.post("/requests", json=REQUEST)
    assert resp.status_code == 201, resp.text
    # First approval is not enough for HIGH data.
    resp = client.post("/requests/api-req-1/approve",
                       json={"approver": "steward-a", "approver_role": "data-steward"})
    assert resp.status_code == 200
    assert resp.json()["status"] == "requested"
    resp = client.post("/requests/api-req-1/approve",
                       json={"approver": "steward-b", "approver_role": "data-steward"})
    assert resp.json()["status"] == "approved"
    # Grant cannot be issued before approval, but now it can.
    resp = client.post("/requests/api-req-1/grant")
    assert resp.status_code == 201, resp.text
    grant_id = resp.json()["grant_id"]
    resp = client.post("/query", json={
        "grant_id": grant_id,
        "columns": ["customer_id", "email", "region"],
        "grantee": "analyst-1"})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["rows_scanned"] == 120
    assert body["rows_returned"] == 100  # default limit
    assert body["columns_masked"] == ["customer_id", "email"]
    assert body["rows"][0]["email"].startswith("hash:")


def test_requester_self_approval_rejected():
    bad = dict(REQUEST, request_id="api-req-self")
    assert client.post("/requests", json=bad).status_code == 201
    resp = client.post("/requests/api-req-self/approve",
                       json={"approver": "analyst-1", "approver_role": "data-steward"})
    assert resp.status_code == 400


def test_bad_purpose_request_rejected():
    bad = dict(REQUEST, request_id="api-req-bad", purpose="reporting")
    assert client.post("/requests", json=bad).status_code == 400


def test_query_unknown_grant_is_404():
    resp = client.post("/query", json={
        "grant_id": "grant-nope", "columns": ["region"]})
    assert resp.status_code == 404


def test_query_out_of_grant_column_forbidden():
    resp = client.post("/query", json={
        "grant_id": "grant-api-req-1", "columns": ["full_name"],
        "grantee": "analyst-1"})
    assert resp.status_code == 403


def test_revoke_then_query_blocked():
    resp = client.post("/grants/grant-api-req-1/revoke",
                       json={"actor": "data-platform", "reason": "test revoke"})
    assert resp.status_code == 200
    assert resp.json()["extracts_revoked"] == 0
    resp = client.post("/query", json={
        "grant_id": "grant-api-req-1", "columns": ["region"],
        "grantee": "analyst-1"})
    assert resp.status_code == 403


def test_compliance_and_audit_endpoints():
    assert client.get("/compliance").status_code == 200
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert any(e["action"] == "grant.issued" for e in resp.json())
