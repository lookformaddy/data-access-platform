"""Pytest configuration: put the src layout on the import path so plain
``pytest`` passes from the project root, with or without an install."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

"""Shared fixtures: a synthetic HIGH-sensitivity customers dataset and a
helper that builds a fully approved grant for it."""
from datetime import datetime, timedelta, timezone

import pytest

from daccess.audit import AuditLog
from daccess.catalog import DatasetCatalog
from daccess.metering import Meter
from daccess.models import (
    AccessRequest,
    ColumnPolicy,
    Dataset,
    Masking,
    Sensitivity,
)
from daccess.query import QueryEngine
from daccess.requests import RequestStore

NOW = datetime(2026, 11, 9, 9, 0, tzinfo=timezone.utc)


def make_dataset() -> Dataset:
    rows = []
    for i in range(60):
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


def make_request(request_id: str = "req-1", **overrides) -> AccessRequest:
    kwargs = {
        "request_id": request_id,
        "dataset": "customers",
        "requester": "analyst-1",
        "requester_role": "analyst",
        "purpose": "model-training",
        "columns": ["customer_id", "email", "region", "segment",
                    "lifetime_value"],
        "column_policies": {
            "email": ColumnPolicy("email", Masking.HASH),
            "customer_id": ColumnPolicy("customer_id", Masking.PARTIAL)},
        "sensitivity": Sensitivity.HIGH,
        "expires_at": NOW + timedelta(days=90),
        "row_budget": 10_000,
        "query_budget": 100,
    }
    kwargs.update(overrides)
    return AccessRequest(**kwargs)


@pytest.fixture
def audit():
    return AuditLog()


@pytest.fixture
def dataset():
    return make_dataset()


@pytest.fixture
def catalog(dataset):
    catalog = DatasetCatalog()
    catalog.register(dataset)
    return catalog


@pytest.fixture
def store(audit):
    return RequestStore(audit=audit)


@pytest.fixture
def approved_grant(store, dataset):
    """A fully approved, issued grant for the customers dataset."""
    request = make_request()
    store.submit(request, dataset, NOW)
    store.approve(request.request_id, "steward-a", "data-steward", NOW)
    store.approve(request.request_id, "steward-b", "data-steward", NOW)
    grant = store.issue_grant(request.request_id, NOW)
    return grant, request


@pytest.fixture
def engine(dataset, audit):
    return QueryEngine({"customers": dataset}, audit=audit)


@pytest.fixture
def meter(approved_grant):
    grant, _ = approved_grant
    return Meter(grant)
