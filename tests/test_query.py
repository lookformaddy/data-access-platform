"""Query engine tests: grant scoping, masking on read, and metering caps."""
import pytest

from conftest import NOW
from daccess.models import AccessError, QueryRequest


def test_query_returns_masked_rows(approved_grant, engine, meter):
    grant, _ = approved_grant
    result = engine.run(grant, QueryRequest(
        grant_id=grant.grant_id,
        columns=["customer_id", "email", "region", "lifetime_value"],
        grantee="analyst-1"), meter, NOW)
    assert result.rows_scanned == 60
    assert result.rows_returned == 60
    assert result.columns_masked == ["customer_id", "email"]
    first = result.rows[0]
    assert first["email"].startswith("hash:")
    assert first["customer_id"] == "CU*****00"
    assert first["region"] == "north"
    assert first["lifetime_value"] == 100.0


def test_query_filters_rows_and_limits(approved_grant, engine, meter):
    grant, _ = approved_grant
    result = engine.run(grant, QueryRequest(
        grant_id=grant.grant_id, columns=["region"],
        row_filter={"region": "south"}, limit=5, grantee="analyst-1"),
        meter, NOW)
    assert result.rows_scanned == 20
    assert result.rows_returned == 5
    assert all(r["region"] == "south" for r in result.rows)


def test_column_outside_grant_denied(approved_grant, engine, meter):
    grant, _ = approved_grant
    with pytest.raises(AccessError):
        engine.run(grant, QueryRequest(
            grant_id=grant.grant_id, columns=["full_name"],
            grantee="analyst-1"), meter, NOW)


def test_wrong_grantee_denied(approved_grant, engine, meter):
    grant, _ = approved_grant
    with pytest.raises(AccessError):
        engine.run(grant, QueryRequest(
            grant_id=grant.grant_id, columns=["region"],
            grantee="someone-else"), meter, NOW)


def test_expired_grant_denied(approved_grant, engine, meter):
    from datetime import timedelta
    grant, _ = approved_grant
    with pytest.raises(AccessError):
        engine.run(grant, QueryRequest(
            grant_id=grant.grant_id, columns=["region"], grantee="analyst-1"),
            meter, NOW + timedelta(days=91))


def test_row_budget_cap_fails_closed_before_serving(approved_grant, engine):
    from daccess.metering import Meter
    grant, _ = approved_grant
    grant.row_budget = 10
    meter = Meter(grant)
    with pytest.raises(AccessError):
        engine.run(grant, QueryRequest(
            grant_id=grant.grant_id, columns=["region"], grantee="analyst-1"),
            meter, NOW)
    # Nothing was consumed by the refused query.
    assert meter.usage.rows_used == 0
    assert meter.usage.queries_used == 0


def test_query_budget_cap(approved_grant, engine):
    from daccess.metering import Meter
    grant, _ = approved_grant
    grant.query_budget = 1
    meter = Meter(grant)
    engine.run(grant, QueryRequest(
        grant_id=grant.grant_id, columns=["region"], grantee="analyst-1"),
        meter, NOW)
    with pytest.raises(AccessError):
        engine.run(grant, QueryRequest(
            grant_id=grant.grant_id, columns=["region"], grantee="analyst-1"),
            meter, NOW)
