# Architecture — Governed Data Access Platform

## Diagram (description)

```
                         ┌──────────────────────┐
                         │   DatasetCatalog     │
                         │  name / columns /    │
                         │  classification      │
                         └──────┬───────────────┘
                                │ register / get
                                ▼
 ┌──────────────┐      ┌──────────────────────┐
 │  Requester   │─────►│  PolicyEngine        │
 │  (role,      │      │  role × classification│
 │   purpose)   │      │  × purpose, fail-    │
 └──────────────┘      │  closed              │
                       └──────┬───────────────┘
                              │ pass
                              ▼
                       ┌──────────────────────┐
                       │  RequestStore        │
                       │  requested → approved│
                       │  (SoD, 2 approvers   │
                       │   for HIGH/RESTRICTED)│
                       │  → denied            │
                       └──────┬───────────────┘
                              │ full approval
                              ▼
                       ┌──────────────────────┐
                       │  Grant               │
                       │  purpose-scoped,     │
                       │  expiring, column    │
                       │  policies + budgets  │
                       └──────┬───────────────┘
                              │
              ┌───────────────┼──────────────────┐
              ▼               ▼                  ▼
       ┌────────────┐  ┌────────────┐     ┌────────────┐
       │ QueryEngine│  │  Meter     │     │ Lifecycle  │
       │ masked     │  │  hard caps │     │ expiry,    │
       │ row select │  │  + burn-   │     │ revoke →   │
       │ over synth │  │  rate      │     │ extracts,  │
       │ in-memory  │  │  forecast  │     │ recertify  │
       │ table      │  └────────────┘     └────────────┘
       └─────┬──────┘         │                  │
             └────────────────┴──────────────────┘
                              ▼
                       ┌──────────────────────┐
                       │  AuditLog            │
                       │  hash-chained,       │
                       │  append-only         │
                       └──────────────────────┘
```

Every operation that changes state or reads data appends to the audit log;
the log is the only cross-cutting dependency, so each module stays
independently testable.

## Module map

| Module | Responsibility |
| --- | --- |
| `models.py` | Dataclasses: Dataset, AccessRequest, Grant, DerivedExtract, QueryRequest/Result, Recertification; error types |
| `catalog.py` | Dataset registration + the role × classification × purpose policy matrix |
| `requests.py` | Request lifecycle, approvals (separation of duties), grant issuance |
| `masking.py` | Column masking: none / partial / full / hash / redact |
| `query.py` | Masked row-select execution against synthetic tables, meter checked first |
| `metering.py` | Per-grant row/query budgets, hard caps, burn-rate forecasts |
| `lifecycle.py` | Expiry sweeps, revocation propagation, recertification, compliance report |
| `audit.py` | Hash-chained append-only audit log with verification |
| `service.py` | FastAPI service over the same core (in-memory state) |
| `cli.py` | argparse CLI (`demo`, `compliance`) over the same core |

## Key flows

**Request → grant.** `submit` runs the policy check (role, purpose,
classification, columns, expiry, budgets). `approve` enforces separation of
duties and the two-approver rule. `issue_grant` refuses anything that is not
fully approved, and stamps the grant with the request's columns, policies,
row filter, expiry, and budgets.

**Query.** The engine verifies the grant is usable (active, unexpired),
the grantee matches, every requested column is inside the grant, and no
forbidden column is requested; then it applies the grant row filter plus
the query filter, checks the meter *before* returning rows, and finally
applies per-column masking.

**Revocation.** `revoke_grant` deactivates the grant and every derived
extract whose `grant_id` matches, and records the reason; other grants'
extracts are untouched. A query against a revoked grant fails closed.

**Recertification.** `open_recertification` creates a review with a due
date; `decide_recertification` with `"confirmed"` keeps the grant, with
`"revoked"` revokes it (and propagates). Overdue, undecided reviews show
up in the compliance report.

## Failure modes

- Policy violation, expired/revoked grant, out-of-grant column, or budget
  overrun: the operation raises `AccessError` (or a subclass) and no state
  changes and no rows are served.
- A request that cannot be approved stays `requested`; a denial requires a
  reason and is terminal.
- Audit tampering (edit, deletion, reordering) is detected by
  `AuditLog.verify()` recomputing the hash chain.

## Production notes

A production deployment would persist requests, grants, meters, and the
audit log in a metadata database, enforce masking at the query planner
rather than in application code, use a KMS-backed secret for hashing,
add an approval notification queue, and run the expiry sweep and
recertification reminders on a schedule. None of that changes the core
invariants implemented here.
