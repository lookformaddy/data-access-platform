"""Per-grant consumption metering with hard caps and burn-rate forecasts."""
from __future__ import annotations

from dataclasses import dataclass

from daccess.models import BudgetExceeded, Grant


@dataclass
class Usage:
    rows_used: int = 0
    queries_used: int = 0


@dataclass
class Forecast:
    rows_remaining: int
    queries_remaining: int
    rows_per_day: float
    days_until_row_exhaustion: float | None
    at_risk: bool  # < 20% of any budget remaining, or < 7 days of rows left


class Meter:
    """One meter per grant. Caps fail closed: exceeding a budget raises
    before any rows are served, and nothing is partially consumed."""

    def __init__(self, grant: Grant):
        self.grant = grant
        self.usage = Usage()

    def consume(self, rows: int) -> Usage:
        if self.usage.queries_used + 1 > self.grant.query_budget:
            raise BudgetExceeded(
                f"grant {self.grant.grant_id!r}: query budget exhausted "
                f"({self.grant.query_budget})")
        if self.usage.rows_used + rows > self.grant.row_budget:
            raise BudgetExceeded(
                f"grant {self.grant.grant_id!r}: row budget exhausted "
                f"({self.grant.row_budget} rows)")
        self.usage.rows_used += rows
        self.usage.queries_used += 1
        return self.usage

    def forecast(self, rows_per_day: float) -> Forecast:
        rows_left = self.grant.row_budget - self.usage.rows_used
        days = (rows_left / rows_per_day) if rows_per_day > 0 else None
        fractions = [
            rows_left / self.grant.row_budget,
            (self.grant.query_budget - self.usage.queries_used)
            / self.grant.query_budget,
        ]
        at_risk = min(fractions) < 0.20 or (days is not None and days < 7)
        return Forecast(
            rows_remaining=rows_left,
            queries_remaining=self.grant.query_budget - self.usage.queries_used,
            rows_per_day=rows_per_day,
            days_until_row_exhaustion=days,
            at_risk=at_risk,
        )
