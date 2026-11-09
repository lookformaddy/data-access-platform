"""FastAPI service for the governed data access platform.

Core is pure stdlib; this module requires FastAPI. State is in-memory.
Every query goes through the same fail-closed path as the CLI:
request -> approvals -> grant -> usable grant -> metering cap ->
masked query execution -> audit.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from daccess.audit import AuditLog
from daccess.catalog import DatasetCatalog
from daccess.lifecycle import (
    compliance_report,
    decide_recertification,
    expire_grants,
    open_recertification,
    revoke_grant,
)
from daccess.metering import Meter
from daccess.models import (
    AccessError,
    ColumnPolicy,
    Dataset,
    Grant,
    Masking,
    QueryRequest,
    Recertification,
    Sensitivity,
    AccessRequest,
)
from daccess.query import QueryEngine
from daccess.requests import RequestStore

app = FastAPI(title="Governed Data Access Platform", version="1.0.0")

AUDIT = AuditLog()
CATALOG = DatasetCatalog()
STORE = RequestStore(audit=AUDIT)
GRANTS: dict[str, Grant] = {}
METERS: dict[str, Meter] = {}
EXTRACTS: list = []
REVIEWS: list[Recertification] = []

DATASETS: dict[str, Dataset] = {
    "customers": Dataset(
        name="customers",
        columns=["customer_id", "email", "full_name", "region", "segment",
                 "lifetime_value"],
        classification=Sensitivity.HIGH,
        rows=[
            {"customer_id": f"CUST-{i:04d}", "email": f"customer{i}@example.com",
             "full_name": f"Customer {i}", "region": r, "segment": s,
             "lifetime_value": 100.0 + (i % 9) * 50.0}
            for i, (r, s) in enumerate(
                [("north", "premium"), ("north", "standard"),
                 ("south", "premium"), ("south", "standard"),
                 ("east", "premium"), ("east", "standard")] * 20)
        ],
    ),
}
for _ds in DATASETS.values():
    CATALOG.register(_ds)
ENGINE = QueryEngine(DATASETS, audit=AUDIT)


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ColumnPolicyIn(BaseModel):
    column: str
    masking: str = "none"
    forbidden: bool = False


class RequestIn(BaseModel):
    request_id: str
    dataset: str
    requester: str
    requester_role: str
    purpose: str
    columns: list[str]
    column_policies: list[ColumnPolicyIn] = []
    row_filter: dict = {}
    sensitivity: str = "medium"
    expires_at: datetime
    row_budget: int = 100_000
    query_budget: int = 1_000


class ApproveIn(BaseModel):
    approver: str
    approver_role: str = "data-steward"


class DenyIn(BaseModel):
    approver: str
    reason: str


class QueryIn(BaseModel):
    grant_id: str
    columns: list[str]
    row_filter: dict = {}
    limit: int = 100
    grantee: str = ""


class RevokeIn(BaseModel):
    actor: str
    reason: str


class ReviewIn(BaseModel):
    reviewer: str
    due_in_days: int = 30


class ReviewDecisionIn(BaseModel):
    decision: str


def _request_from_in(body: RequestIn) -> AccessRequest:
    return AccessRequest(
        request_id=body.request_id, dataset=body.dataset,
        requester=body.requester, requester_role=body.requester_role,
        purpose=body.purpose, columns=body.columns,
        column_policies={p.column: ColumnPolicy(p.column, Masking(p.masking),
                                                p.forbidden)
                         for p in body.column_policies},
        row_filter=body.row_filter, sensitivity=Sensitivity(body.sensitivity),
        expires_at=body.expires_at, row_budget=body.row_budget,
        query_budget=body.query_budget)


@app.post("/requests", status_code=201)
def submit_request(body: RequestIn):
    try:
        dataset = CATALOG.get(body.dataset)
        request = STORE.submit(_request_from_in(body), dataset, _now())
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"request_id": request.request_id, "status": request.status.value}


@app.get("/requests")
def list_requests():
    return [{"request_id": r.request_id, "dataset": r.dataset,
             "requester": r.requester, "status": r.status.value,
             "sensitivity": r.sensitivity.value, "approvals": r.approvals}
            for r in STORE.list()]


@app.post("/requests/{request_id}/approve")
def approve_request(request_id: str, body: ApproveIn):
    try:
        request = STORE.approve(request_id, body.approver,
                                body.approver_role, _now())
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"request_id": request_id, "status": request.status.value,
            "approvals": request.approvals}


@app.post("/requests/{request_id}/deny")
def deny_request(request_id: str, body: DenyIn):
    try:
        request = STORE.deny(request_id, body.approver, body.reason)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"request_id": request_id, "status": request.status.value}


@app.post("/requests/{request_id}/grant", status_code=201)
def issue_grant(request_id: str):
    try:
        grant = STORE.issue_grant(request_id, _now())
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    GRANTS[grant.grant_id] = grant
    METERS[grant.grant_id] = Meter(grant)
    return {"grant_id": grant.grant_id, "grantee": grant.grantee,
            "expires_at": grant.expires_at.isoformat() if grant.expires_at else None}


@app.get("/grants")
def list_grants():
    return [{"grant_id": g.grant_id, "dataset": g.dataset, "grantee": g.grantee,
             "purpose": g.purpose, "active": g.active,
             "expires_at": g.expires_at.isoformat() if g.expires_at else None}
            for g in GRANTS.values()]


@app.post("/query")
def run_query(body: QueryIn):
    grant = GRANTS.get(body.grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="unknown grant")
    try:
        meter = METERS.setdefault(grant.grant_id, Meter(grant))
        result = ENGINE.run(grant, QueryRequest(**body.model_dump()), meter,
                            _now())
    except AccessError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    return {"grant_id": result.grant_id, "rows": result.rows,
            "rows_scanned": result.rows_scanned,
            "rows_returned": result.rows_returned,
            "columns_masked": result.columns_masked}


@app.post("/grants/{grant_id}/revoke")
def revoke(grant_id: str, body: RevokeIn):
    grant = GRANTS.get(grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="unknown grant")
    try:
        propagated = revoke_grant(grant, body.actor, body.reason, EXTRACTS, AUDIT)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"grant_id": grant_id, "active": False,
            "extracts_revoked": len(propagated)}


@app.post("/grants/{grant_id}/recertify", status_code=201)
def open_review(grant_id: str, body: ReviewIn):
    grant = GRANTS.get(grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="unknown grant")
    try:
        review = open_recertification(grant, body.reviewer, body.due_in_days,
                                      _now(), AUDIT)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    REVIEWS.append(review)
    return {"review_id": review.review_id, "grant_id": grant_id,
            "due_at": review.due_at.isoformat()}


@app.post("/reviews/{review_id}/decide")
def decide_review(review_id: str, body: ReviewDecisionIn):
    review = next((r for r in REVIEWS if r.review_id == review_id), None)
    if review is None:
        raise HTTPException(status_code=404, detail="unknown review")
    grant = GRANTS.get(review.grant_id)
    if grant is None:
        raise HTTPException(status_code=404, detail="unknown grant")
    try:
        decide_recertification(review, grant, body.decision, _now(), EXTRACTS, AUDIT)
    except AccessError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"review_id": review_id, "decision": review.decision,
            "grant_active": grant.active}


@app.get("/compliance")
def compliance():
    expire_grants(list(GRANTS.values()), STORE.list(), _now(), AUDIT)
    return compliance_report(list(GRANTS.values()), STORE.list(), REVIEWS, _now())


@app.get("/audit")
def audit():
    return [{"seq": e.seq, "timestamp": e.timestamp, "actor": e.actor,
             "action": e.action, "grant_id": e.grant_id,
             "entry_hash": e.entry_hash[:16]}
            for e in AUDIT.entries]
