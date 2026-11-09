"""Query execution against a synthetic in-memory table.

Every query runs through the same fail-closed path:
grant usable (active, unexpired, grantee match) -> requested columns are
within the grant -> row filter intersected with the grant's filter ->
rows capped at the grant's meter -> masking applied per column policy.
A query that would exceed the row budget is refused before any row is
returned, so no partial results ever leak.
"""
from __future__ import annotations

from daccess.audit import AuditLog
from daccess.masking import apply_column_policies
from daccess.metering import Meter
from daccess.models import (
    AccessError,
    Dataset,
    Grant,
    PolicyViolation,
    QueryRequest,
    QueryResult,
)


class QueryEngine:
    def __init__(self, datasets: dict[str, Dataset], audit: AuditLog | None = None,
                 salt: str = "daccess"):
        self.datasets = datasets
        self.audit = audit
        self.salt = salt

    def run(self, grant: Grant, query: QueryRequest, meter: Meter,
            now=None) -> QueryResult:
        if now is not None and not grant.is_usable(now):
            raise AccessError(f"grant {grant.grant_id!r} is not usable")
        if query.grantee and query.grantee != grant.grantee:
            raise AccessError(
                f"grant {grant.grant_id!r} belongs to {grant.grantee!r}")
        if query.grant_id != grant.grant_id:
            raise AccessError("query grant_id does not match the grant")
        dataset = self.datasets.get(grant.dataset)
        if dataset is None:
            raise AccessError(f"unknown dataset {grant.dataset!r}")
        outside = [c for c in query.columns if c not in grant.columns]
        if outside:
            raise PolicyViolation(
                f"columns outside the grant: {outside}")
        forbidden = [c for c in query.columns
                     if grant.column_policies.get(c) is not None
                     and grant.column_policies[c].forbidden]
        if forbidden:
            raise PolicyViolation(f"forbidden columns requested: {forbidden}")
        if query.limit <= 0:
            raise PolicyViolation("limit must be positive")

        # Grant row filter always applies; the query filter narrows further.
        rows = dataset.filtered_rows(grant.row_filter)
        rows = [r for r in rows
                if all(r.get(k) == v for k, v in query.row_filter.items())]
        rows_scanned = len(rows)
        # Meter check happens BEFORE any row is returned.
        meter.consume(rows_scanned)

        masked_rows: list[dict[str, Any]] = []
        masked_columns: set[str] = set()
        for row in rows[: query.limit]:
            selected = {c: row.get(c) for c in query.columns}
            masked_row, masked = apply_column_policies(selected,
                                                       grant.column_policies,
                                                       self.salt)
            masked_columns.update(masked)
            masked_rows.append(masked_row)
        if self.audit:
            self.audit.append("query.executed", query.grantee or grant.grantee,
                              grant.grant_id,
                              {"columns": query.columns,
                               "rows_scanned": rows_scanned,
                               "rows_returned": len(masked_rows)})
        return QueryResult(
            grant_id=grant.grant_id,
            rows=masked_rows,
            rows_scanned=rows_scanned,
            rows_returned=len(masked_rows),
            columns_masked=sorted(masked_columns),
        )
