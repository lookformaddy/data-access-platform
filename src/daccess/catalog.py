"""Dataset catalog with classification, and the policy engine.

Policy is a role x classification x purpose matrix evaluated fail-closed:
an unknown role, an unknown purpose, a purpose not allowed for the
dataset's classification, or a request touching a forbidden column is
denied — never defaulted to a permissive answer.
"""
from __future__ import annotations

from daccess.models import AccessError, AccessRequest, Dataset, PolicyViolation, Sensitivity

# Roles the platform recognises. Anything else is denied outright.
KNOWN_ROLES = {"analyst", "data-scientist", "engineer", "data-steward",
               "auditor", "product-manager"}

# Purposes the platform recognises, and the highest classification each
# purpose may touch. A purpose that is not listed is denied.
PURPOSE_MAX_SENSITIVITY: dict[str, Sensitivity] = {
    "reporting": Sensitivity.MEDIUM,
    "product-analytics": Sensitivity.MEDIUM,
    "model-training": Sensitivity.HIGH,
    "fraud-investigation": Sensitivity.RESTRICTED,
    "audit": Sensitivity.RESTRICTED,
    "customer-support": Sensitivity.LOW,
}

_SENSITIVITY_RANK = {
    Sensitivity.LOW: 0,
    Sensitivity.MEDIUM: 1,
    Sensitivity.HIGH: 2,
    Sensitivity.RESTRICTED: 3,
}

# Roles that may approve access for each classification. Data stewards
# approve up to HIGH; RESTRICTED needs a steward *and* a second approver
# (enforced in requests.py), and auditors never approve their own access.
APPROVER_ROLES: dict[Sensitivity, set[str]] = {
    Sensitivity.LOW: {"data-steward", "analyst"},
    Sensitivity.MEDIUM: {"data-steward"},
    Sensitivity.HIGH: {"data-steward"},
    Sensitivity.RESTRICTED: {"data-steward"},
}


class DatasetCatalog:
    def __init__(self):
        self.datasets: dict[str, Dataset] = {}

    def register(self, dataset: Dataset) -> Dataset:
        if dataset.name in self.datasets:
            raise AccessError(f"dataset {dataset.name!r} is already registered")
        if not dataset.columns:
            raise AccessError(f"dataset {dataset.name!r} has no columns")
        self.datasets[dataset.name] = dataset
        return dataset

    def get(self, name: str) -> Dataset:
        try:
            return self.datasets[name]
        except KeyError:
            raise AccessError(f"unknown dataset {name!r}") from None

    def list(self) -> list[Dataset]:
        return list(self.datasets.values())


def check_request_policy(request: AccessRequest, dataset: Dataset) -> None:
    """Fail-closed policy check for an access request. Raises on any violation."""
    if request.requester_role not in KNOWN_ROLES:
        raise PolicyViolation(f"unknown role {request.requester_role!r}")
    if not request.purpose.strip():
        raise PolicyViolation("a purpose is required for every access request")
    max_allowed = PURPOSE_MAX_SENSITIVITY.get(request.purpose)
    if max_allowed is None:
        raise PolicyViolation(f"unknown purpose {request.purpose!r}")
    if _SENSITIVITY_RANK[dataset.classification] > _SENSITIVITY_RANK[max_allowed]:
        raise PolicyViolation(
            f"purpose {request.purpose!r} may not access "
            f"{dataset.classification.value}-sensitivity data")
    if request.sensitivity != dataset.classification:
        raise PolicyViolation(
            f"request sensitivity {request.sensitivity.value} does not match "
            f"dataset classification {dataset.classification.value}")
    if not request.columns:
        raise PolicyViolation("at least one column must be requested")
    unknown = [c for c in request.columns if c not in dataset.columns]
    if unknown:
        raise PolicyViolation(f"unknown columns for dataset {dataset.name!r}: {unknown}")
    forbidden = [c for c in request.columns
                 if request.policy_for(c).forbidden]
    if forbidden:
        raise PolicyViolation(f"forbidden columns requested: {forbidden}")
    if request.expires_at is None:
        raise PolicyViolation("an expiry is required for every grant")
    if request.row_budget <= 0 or request.query_budget <= 0:
        raise PolicyViolation("budgets must be positive")


def required_approvals(sensitivity: Sensitivity) -> int:
    """Two approvers for HIGH and RESTRICTED data, one otherwise."""
    return 2 if sensitivity in (Sensitivity.HIGH, Sensitivity.RESTRICTED) else 1


def may_approve(sensitivity: Sensitivity, approver_role: str) -> bool:
    return approver_role in APPROVER_ROLES.get(sensitivity, set())
