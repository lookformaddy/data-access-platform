"""Metering tests: hard caps and burn-rate forecasts."""
import pytest

from conftest import NOW
from daccess.metering import Meter
from daccess.models import AccessError


def test_consume_tracks_usage(approved_grant):
    grant, _ = approved_grant
    meter = Meter(grant)
    usage = meter.consume(100)
    assert usage.rows_used == 100
    assert usage.queries_used == 1


def test_row_cap_raises_and_consumes_nothing(approved_grant):
    grant, _ = approved_grant
    grant.row_budget = 50
    meter = Meter(grant)
    with pytest.raises(AccessError):
        meter.consume(51)
    assert meter.usage.rows_used == 0


def test_query_cap_raises(approved_grant):
    grant, _ = approved_grant
    grant.query_budget = 1
    meter = Meter(grant)
    meter.consume(10)
    with pytest.raises(AccessError):
        meter.consume(10)


def test_forecast_days_and_at_risk(approved_grant):
    grant, _ = approved_grant
    grant.row_budget = 1_000
    meter = Meter(grant)
    meter.consume(900)
    forecast = meter.forecast(rows_per_day=50)
    assert forecast.rows_remaining == 100
    assert forecast.days_until_row_exhaustion == pytest.approx(2.0)
    assert forecast.at_risk  # only 10% of rows left


def test_forecast_no_burn_rate(approved_grant):
    grant, _ = approved_grant
    meter = Meter(grant)
    forecast = meter.forecast(rows_per_day=0)
    assert forecast.days_until_row_exhaustion is None
    assert not forecast.at_risk
