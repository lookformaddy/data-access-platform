"""Hash-chained audit log tests."""
import pytest

from daccess.audit import AuditLog


def test_chain_verifies_and_detects_tampering():
    audit = AuditLog()
    audit.append("request.submitted", "analyst-1", "req-1", {"dataset": "customers"})
    audit.append("request.approved", "steward-a", "req-1", {})
    audit.append("grant.issued", "system", "grant-req-1", {})
    assert audit.verify()
    assert [e.seq for e in audit.entries] == [1, 2, 3]
    assert audit.entries[0].prev_hash == "GENESIS"
    assert audit.entries[1].prev_hash == audit.entries[0].entry_hash
    # Tamper with a stored entry: the chain no longer verifies.
    audit.entries[1].details["dataset"] = "other"
    assert not audit.verify()


def test_for_grant_filters():
    audit = AuditLog()
    audit.append("query.executed", "analyst-1", "grant-1", {})
    audit.append("query.executed", "analyst-2", "grant-2", {})
    assert len(audit.for_grant("grant-1")) == 1
    assert len(audit.for_grant("grant-2")) == 1
