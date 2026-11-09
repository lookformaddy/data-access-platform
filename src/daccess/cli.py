"""CLI over the same core as the FastAPI service.

Usage:
    PYTHONPATH=src python3 -m daccess.cli demo
    PYTHONPATH=src python3 -m daccess.cli compliance
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone

from daccess.audit import AuditLog
from daccess.catalog import DatasetCatalog
from daccess.lifecycle import compliance_report, expire_grants
from daccess.metering import Meter
from daccess.models import (
    ColumnPolicy,
    Dataset,
    Masking,
    QueryRequest,
    Sensitivity,
    AccessRequest,
)
from daccess.query import QueryEngine
from daccess.requests import RequestStore


def _seed() -> tuple[RequestStore, QueryEngine, AuditLog, dict, DatasetCatalog]:
    audit = AuditLog()
    catalog = DatasetCatalog()
    store = RequestStore(audit=audit)
    now = datetime(2026, 11, 9, tzinfo=timezone.utc)
    dataset = Dataset(
        name="customers",
        columns=["customer_id", "email", "full_name", "region", "segment",
                 "lifetime_value"],
        classification=Sensitivity.HIGH,
        rows=[{"customer_id": f"CUST-{i:04d}",
               "email": f"customer{i}@example.com",
               "full_name": f"Customer {i}", "region": r, "segment": s,
               "lifetime_value": 100.0 + (i % 9) * 50.0}
              for i, (r, s) in enumerate(
                  [("north", "premium"), ("north", "standard"),
                   ("south", "premium"), ("south", "standard"),
                   ("east", "premium"), ("east", "standard")] * 20)],
    )
    catalog.register(dataset)
    request = AccessRequest(
        request_id="req-customers-analytics", dataset="customers",
        requester="analyst-1", requester_role="analyst",
        purpose="model-training",
        columns=["customer_id", "email", "region", "segment", "lifetime_value"],
        column_policies={
            "email": ColumnPolicy("email", Masking.HASH),
            "customer_id": ColumnPolicy("customer_id", Masking.PARTIAL)},
        sensitivity=Sensitivity.HIGH,
        expires_at=now + timedelta(days=90), row_budget=10_000, query_budget=100)
    store.submit(request, dataset, now)
    store.approve(request.request_id, "steward-a", "data-steward", now)
    store.approve(request.request_id, "steward-b", "data-steward", now)
    grant = store.issue_grant(request.request_id, now)
    engine = QueryEngine({"customers": dataset}, audit=audit)
    return store, engine, audit, {grant.grant_id: (grant, Meter(grant))}, catalog


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="daccess")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="run a masked query against the seeded grant")
    sub.add_parser("compliance", help="print the compliance report")
    args = parser.parse_args(argv)
    store, engine, audit, grants, catalog = _seed()
    now = datetime(2026, 11, 9, tzinfo=timezone.utc)
    if args.command == "compliance":
        expire_grants([g for g, _ in grants.values()], store.list(), now, audit)
        print(json.dumps(compliance_report(
            [g for g, _ in grants.values()], store.list(), [], now), indent=2))
        return 0
    grant, meter = next(iter(grants.values()))
    result = engine.run(grant, QueryRequest(
        grant_id=grant.grant_id,
        columns=["customer_id", "email", "region", "lifetime_value"],
        grantee="analyst-1"), meter, now)
    print(json.dumps({"rows": result.rows[:3], "rows_scanned": result.rows_scanned,
                      "rows_returned": result.rows_returned,
                      "columns_masked": result.columns_masked}, indent=2))
    print(f"audit entries: {len(audit.entries)}, chain valid: {audit.verify()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
