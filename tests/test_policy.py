"""Policy engine tests: fail-closed role / purpose / classification checks."""
from datetime import timedelta

import pytest

from conftest import NOW, make_request
from daccess.catalog import check_request_policy
from daccess.models import AccessError, ColumnPolicy, Masking, Sensitivity


def test_valid_high_request_passes(dataset):
    check_request_policy(make_request(), dataset)


def test_unknown_role_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(requester_role="superuser"), dataset)


def test_unknown_purpose_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(purpose="curiosity"), dataset)


def test_purpose_below_classification_denied(dataset):
    # "reporting" may only touch up to MEDIUM; dataset is HIGH.
    with pytest.raises(AccessError):
        check_request_policy(make_request(purpose="reporting"), dataset)


def test_empty_purpose_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(purpose=""), dataset)


def test_sensitivity_mismatch_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(sensitivity=Sensitivity.MEDIUM),
                             dataset)


def test_unknown_column_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(columns=["ssn"]), dataset)


def test_forbidden_column_denied(dataset):
    request = make_request(
        columns=["full_name"],
        column_policies={"full_name": ColumnPolicy("full_name", Masking.NONE,
                                                   forbidden=True)})
    with pytest.raises(AccessError):
        check_request_policy(request, dataset)


def test_missing_expiry_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(expires_at=None), dataset)


def test_non_positive_budget_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(row_budget=0), dataset)


def test_no_columns_denied(dataset):
    with pytest.raises(AccessError):
        check_request_policy(make_request(columns=[]), dataset)


def test_catalog_rejects_duplicate_and_unknown(catalog):
    from daccess.models import Dataset
    with pytest.raises(AccessError):
        catalog.register(Dataset(name="customers", columns=["x"]))
    with pytest.raises(AccessError):
        catalog.get("no-such-dataset")
