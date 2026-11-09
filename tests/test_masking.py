"""Masking policy tests."""
import pytest

from daccess.masking import apply_column_policies, mask_value
from daccess.models import ColumnPolicy, Masking


def test_partial_masking():
    assert mask_value("customer42@example.com", Masking.PARTIAL) == "cu" + "*" * 18 + "om"
    assert mask_value("CUST-0001", Masking.PARTIAL) == "CU*****01"


def test_partial_short_value():
    assert mask_value("abc", Masking.PARTIAL) == "***"


def test_full_masking():
    assert mask_value("secret", Masking.FULL) == "***"


def test_hash_masking_deterministic_and_opaque():
    first = mask_value("customer42@example.com", Masking.HASH)
    second = mask_value("customer42@example.com", Masking.HASH)
    assert first == second
    assert first.startswith("hash:")
    assert "customer42" not in first
    assert mask_value("other@example.com", Masking.HASH) != first


def test_none_masking_passthrough():
    assert mask_value(42, Masking.NONE) == 42
    assert mask_value(None, Masking.FULL) is None


def test_apply_policies_drops_redacted_and_reports_masked():
    row = {"email": "a@example.com", "region": "north", "ssn": "123-45-6789"}
    policies = {
        "email": ColumnPolicy("email", Masking.HASH),
        "ssn": ColumnPolicy("ssn", Masking.REDACT),
    }
    masked_row, masked = apply_column_policies(row, policies)
    assert "ssn" not in masked_row
    assert masked_row["region"] == "north"
    assert masked_row["email"].startswith("hash:")
    assert sorted(masked) == ["email", "ssn"]
