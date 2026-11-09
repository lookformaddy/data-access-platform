# Governed Data Access Platform

A governed self-serve data access platform: dataset access requests with an approval workflow (two approvers for sensitive data, separation of duties), purpose-scoped expiring grants, masked views with column-level masking policies, query auditing with a hash-chained audit log, per-grant usage metering with hard caps and burn-rate forecasts, revocation that propagates to derived extracts, access reviews / recertification, and compliance reporting — all on synthetic data.

## The enterprise problem

Self-serve data access usually fails in one of two ways: either every request becomes a ticket that takes weeks, or access is handed out once and never revisited. In a regulated enterprise, access has to be *governed by construction*: every grant starts from a declared purpose, is approved by the right people (never by the requester, two approvers for sensitive data), expires on a date, is scoped to exactly the columns and rows the purpose needs, masks what the grantee must not see in the clear, is metered against budgets that fail closed, can be revoked in one place with the revocation reaching every derived extract, and is re-confirmed on a schedule. This project implements that control plane as a deterministic, dependency-light Python service.

## Architecture overview

```
DatasetCatalog ──► PolicyEngine (role × classification × purpose, fail-closed)
     │                    │
     │                    ▼
     │              RequestStore ──► approve (SoD, 2 approvers for HIGH/RESTRICTED)
     │                    │              │
     │                    │              ▼
     │                    │         Grant (purpose-scoped, expiring)
     │                    │              │
     │                    ▼              ▼
     │              QueryEngine ──► masking (full/redact/hash/partial)
     │                    │              │
     │                    ├─► Meter ──► hard caps + burn-rate forecast
     │                    └─► AuditLog (hash-chained, tamper-evident)
     └─► Lifecycle ──► expiry sweeps, revocation propagation,
                        recertification, compliance reporting
```

- **Catalog & policy** (`src/daccess/catalog.py`) — datasets register with a classification; the policy engine is a role × classification × purpose matrix. Unknown roles, unknown purposes, a purpose below the dataset's classification, a sensitivity mismatch, forbidden columns, or a missing expiry are all denied, never defaulted.
- **Requests** (`requests.py`) — lifecycle requested → approved → active (grant issued) → expired/revoked. Separation of duties: the requester can never approve their own request, an approver cannot approve twice, and HIGH/RESTRICTED data needs two distinct data stewards. Denials require a reason. A grant is issued only after full approval.
- **Masking** (`masking.py`) — per-column policies: none, partial (first/last 2 chars), full, hash (deterministic salted SHA-256, joinable but not reversible), redact (column dropped from results).
- **Query engine** (`query.py`) — runs a select against a synthetic in-memory table. The grant's row filter always applies, requested columns must be inside the grant, the meter is checked *before* any row is returned, and masking is applied per column policy.
- **Metering** (`metering.py`) — per-grant row/query budgets. Consumption past any cap raises instead of serving, and nothing is partially consumed. Forecasts project days until row exhaustion from a burn rate and flag at-risk grants (<20% of any budget, or <7 days left).
- **Lifecycle** (`lifecycle.py`) — expiry sweeps mark past-due grants expired; revocation requires a reason and propagates to every derived extract of that grant (and only that grant); recertification opens an access review the dataset owner must confirm or the grant is revoked; compliance reporting counts grants by sensitivity/status and flags expired-but-active grants and overdue reviews.
- **Audit log** (`audit.py`) — every request, approval, grant, query, revocation, and review decision appends a hash-chained entry; any edit, deletion, or reordering is detectable.
- **API + CLI** (`service.py`, `cli.py`) — FastAPI service and an argparse CLI over the same core.

## How to run

```bash
pip install -r requirements.txt   # core is pure stdlib; FastAPI/pytest are optional extras
PYTHONPATH=src python3 scripts/demo.py        # end-to-end demo (offline, synthetic data)
PYTHONPATH=src python3 -m pytest tests/ -q   # test suite
PYTHONPATH=src python3 -m daccess.cli demo
uvicorn daccess.service:app --host 0.0.0.0 --port 8000   # API (needs FastAPI)
```

## Key design decisions and trade-offs

- **Fail-closed everywhere.** Invalid requests are rejected, not defaulted; revoked/expired grants serve nothing; out-of-grant columns fail before any row is read; budget overruns raise before any rows are consumed.
- **Requests, not standing access.** Nothing is granted without a declared purpose and an expiry; the grant is the only thing the query engine trusts, so there is no path to data that bypasses approval.
- **Separation of duties as code.** The requester-approval ban and the two-approver rule for sensitive data are enforced in the request store, not left to process — the API cannot issue a grant for a half-approved request.
- **Deterministic hashing.** Salted SHA-256 hashes keep joins working across grants without storing plaintext; a production system would use a keyed HMAC with a rotated secret and a token vault for reversible cases.
- **In-memory store.** Datasets, requests, grants, and meters are in-memory by design for this portfolio project; the core is deliberately split from storage so a durable backend (metadata DB + object store) can replace it without touching policy, request, query, or lifecycle logic.
- **CI shipped as `docs/github-actions-ci.yml`.** The GitHub App used to publish this repo lacks the Workflows permission, so the workflow activates by moving that file to `.github/workflows/ci.yml`.

## What it demonstrates

Governed self-serve data access, policy enforcement as a role × classification × purpose matrix, approval workflows with separation of duties and two-approver sign-off for sensitive data, purpose-scoped expiring grants, column-level masking (partial/full/hash/redact), metered query execution with hard caps and burn-rate forecasts, revocation propagation to derived extracts, recertification / access reviews, compliance reporting, and tamper-evident auditing — the controls a Director-level data engineering interview probes when asking "how do you give people data access without losing control of it?"
