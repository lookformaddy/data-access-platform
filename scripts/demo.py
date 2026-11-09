"""End-to-end demo: catalog + policy, access requests with two-approver
sign-off, grants, masking, masked queries, metering with burn-rate
forecasts, revocation propagation, recertification, compliance reporting,
and the hash-chained audit log.

Deterministic, offline, synthetic data only. Run with:
    PYTHONPATH=src python3 scripts/demo.py
"""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from daccess.audit import AuditLog
from daccess.catalog import DatasetCatalog
from daccess.lifecycle import (
    compliance_report,
    decide_recertification,
    expire_grants,
    open_recertification,
    revoke_grant,
)
from daccess.masking import apply_column_policies
from daccess.metering import Meter
from daccess.models import (
    AccessError,
    AccessRequest,
    ColumnPolicy,
    Dataset,
    DerivedExtract,
    Masking,
    QueryRequest,
    Sensitivity,
)
from daccess.query import QueryEngine
from daccess.requests import RequestStore

NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)


def seed_dataset() -> Dataset:
    rows = []
    for i in range(120):
        region, segment = [("north", "premium"), ("north", "standard"),
                           ("south", "premium"), ("south", "standard"),
                           ("east", "premium"), ("east", "standard")][i % 6]
        rows.append({
            "customer_id": f"CUST-{i:04d}",
            "email": f"customer{i}@example.com",
            "full_name": f"Customer {i}",
            "region": region,
            "segment": segment,
            "lifetime_value": 100.0 + (i % 9) * 50.0,
        })
    return Dataset(name="customers",
                   columns=["customer_id", "email", "full_name", "region",
                            "segment", "lifetime_value"],
                   classification=Sensitivity.HIGH, rows=rows)


def main() -> None:
    audit = AuditLog()
    catalog = DatasetCatalog()
    store = RequestStore(audit=audit)
    dataset = seed_dataset()
    catalog.register(dataset)
    engine = QueryEngine({"customers": dataset}, audit=audit)
    blocked = 0

    # 1. Fail-closed policy: a purpose that cannot touch HIGH data is denied,
    #    and so is a request for a forbidden column.
    for bad in (
        AccessRequest(request_id="bad-purpose", dataset="customers",
                      requester="analyst-1", requester_role="analyst",
                      purpose="reporting", columns=["region"],
                      sensitivity=Sensitivity.HIGH,
                      expires_at=NOW + timedelta(days=30)),
        AccessRequest(request_id="bad-column", dataset="customers",
                      requester="analyst-1", requester_role="analyst",
                      purpose="model-training", columns=["full_name"],
                      column_policies={"full_name": ColumnPolicy(
                          "full_name", Masking.NONE, forbidden=True)},
                      sensitivity=Sensitivity.HIGH,
                      expires_at=NOW + timedelta(days=30)),
    ):
        try:
            store.submit(bad, dataset, NOW)
            print(f"[policy] {bad.request_id}: NOT blocked (unexpected)")
        except AccessError as exc:
            blocked += 1
            print(f"[policy] rejected {bad.request_id}: {exc}")

    # 2. A valid HIGH-sensitivity request: model training with hashed email
    #    and partially masked customer ids.
    request = AccessRequest(
        request_id="req-customers-ml", dataset="customers",
        requester="analyst-1", requester_role="analyst",
        purpose="model-training",
        columns=["customer_id", "email", "region", "segment", "lifetime_value"],
        column_policies={
            "email": ColumnPolicy("email", Masking.HASH),
            "customer_id": ColumnPolicy("customer_id", Masking.PARTIAL)},
        sensitivity=Sensitivity.HIGH,
        expires_at=NOW + timedelta(days=90), row_budget=500, query_budget=50)
    store.submit(request, dataset, NOW)
    print(f"[requests] submitted {request.request_id} "
          f"(sensitivity={request.sensitivity.value}, status={request.status.value})")

    # 3. Separation of duties: the requester cannot approve; one approver is
    #    not enough for HIGH data; two distinct stewards complete approval.
    for approver, role in (("analyst-1", "analyst"), ("steward-a", "data-steward"),
                          ("steward-a", "data-steward"),
                          ("steward-b", "data-steward")):
        try:
            store.approve(request.request_id, approver, role, NOW)
            print(f"[approvals] {approver} approved "
                  f"({len(request.approvals)}/2, status={request.status.value})")
        except AccessError as exc:
            blocked += 1
            print(f"[approvals] blocked {approver}: {exc}")

    grant = store.issue_grant(request.request_id, NOW)
    print(f"[grants] issued {grant.grant_id} for {grant.grantee}, "
          f"expires {grant.expires_at.date()}, row budget {grant.row_budget}")
    meter = Meter(grant)

    # 4. Masked query: email is hashed, customer id partially masked,
    #    full_name is not in the grant so it cannot be requested.
    result = engine.run(grant, QueryRequest(
        grant_id=grant.grant_id,
        columns=["customer_id", "email", "region", "lifetime_value"],
        grantee="analyst-1"), meter, NOW)
    print(f"[query] {result.rows_returned} rows returned "
          f"({result.rows_scanned} scanned), masked={result.columns_masked}")
    print(f"    sample: {result.rows[0]}")
    try:
        engine.run(grant, QueryRequest(
            grant_id=grant.grant_id, columns=["full_name"],
            grantee="analyst-1"), meter, NOW)
        print("[query] out-of-grant column: NOT blocked (unexpected)")
    except AccessError as exc:
        blocked += 1
        print(f"[query] blocked out-of-grant column: {exc}")

    # 5. Metering: burn the row budget, then the cap fails closed.
    print(f"[metering] rows used: {meter.usage.rows_used}/{grant.row_budget} "
          f"after {meter.usage.queries_used} query")
    try:
        meter.consume(400)
    except AccessError as exc:
        blocked += 1
        print(f"[metering] cap enforced: {exc}")
    forecast = meter.forecast(rows_per_day=60)
    print(f"[metering] forecast: {forecast.rows_remaining} rows left, "
          f"{forecast.days_until_row_exhaustion:.1f} days at 60 rows/day, "
          f"at_risk={forecast.at_risk}")

    # 6. Recertification: owner confirms the grant, so it stays active.
    review = open_recertification(grant, "data-platform", 30, NOW, audit)
    decide_recertification(review, grant, "confirmed", NOW, audit=audit)
    print(f"[recertification] {review.review_id}: {review.decision}, "
          f"grant still active={grant.active}")

    # 7. Revocation propagates to derived extracts of this grant only.
    extracts = [DerivedExtract("ext-1", grant.grant_id, "training snapshot"),
                DerivedExtract("ext-2", "grant-other", "unrelated extract")]
    propagated = revoke_grant(grant, "data-platform", "purpose no longer valid",
                              extracts, audit)
    print(f"[lifecycle] revoked {grant.grant_id}: {len(propagated)} derived "
          f"extract(s) revoked, unrelated extract still active={extracts[1].active}")
    try:
        engine.run(grant, QueryRequest(
            grant_id=grant.grant_id, columns=["region"], grantee="analyst-1"),
            meter, NOW)
        print("[lifecycle] query on revoked grant: NOT blocked (unexpected)")
    except AccessError as exc:
        blocked += 1
        print(f"[lifecycle] blocked query on revoked grant: {exc}")

    # 8. Compliance + audit chain.
    expire_grants([grant], store.list(), NOW, audit)
    report = compliance_report([grant], store.list(), [review], NOW)
    print(f"[compliance] total_grants={report['total_grants']} "
          f"active={report['active_grants']} "
          f"by_sensitivity={report['by_sensitivity']} "
          f"expired_but_active={report['expired_but_active']} "
          f"overdue_reviews={report['overdue_reviews']}")
    print(f"[audit] entries={len(audit.entries)} chain_valid={audit.verify()}")
    print(f"[summary] grants=1 queries_blocked={blocked} demo complete")


if __name__ == "__main__":
    main()
