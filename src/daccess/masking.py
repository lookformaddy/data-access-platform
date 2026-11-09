"""Column-level masking policies.

- none: value returned as-is.
- partial: first 2 and last 2 characters shown, middle replaced with '*'.
- full: the whole value replaced with '***'.
- hash: deterministic salted SHA-256 digest (joinable, not reversible).
- redact: the column is dropped from results entirely.
"""
from __future__ import annotations

import hashlib
from typing import Any

from daccess.models import ColumnPolicy, Masking

MASK_TOKEN = "***"


def mask_value(value: Any, masking: Masking, salt: str = "daccess") -> Any:
    if value is None:
        return None
    text = str(value)
    if masking is Masking.NONE:
        return value
    if masking is Masking.FULL:
        return MASK_TOKEN
    if masking is Masking.PARTIAL:
        if len(text) <= 4:
            return "*" * len(text)
        return text[:2] + "*" * (len(text) - 4) + text[-2:]
    if masking is Masking.HASH:
        digest = hashlib.sha256(f"{salt}:{text}".encode()).hexdigest()
        return f"hash:{digest[:16]}"
    if masking is Masking.REDACT:
        raise ValueError("redacted columns are dropped, not masked")
    raise ValueError(f"unknown masking {masking!r}")


def apply_column_policies(row: dict[str, Any],
                          policies: dict[str, ColumnPolicy],
                          salt: str = "daccess") -> tuple[dict[str, Any], list[str]]:
    """Apply per-column policies to one row. Returns (masked row, masked columns)."""
    out: dict[str, Any] = {}
    masked: list[str] = []
    for column, value in row.items():
        policy = policies.get(column)
        if policy is None or policy.masking is Masking.NONE:
            out[column] = value
            continue
        if policy.masking is Masking.REDACT:
            masked.append(column)
            continue
        out[column] = mask_value(value, policy.masking, salt)
        masked.append(column)
    return out, masked
