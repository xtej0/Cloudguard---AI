from __future__ import annotations


DEFAULT_MITIGATIONS = [
    "Restrict public exposure",
    "Apply least privilege IAM policies",
    "Patch critical vulnerabilities",
]


def get_mitigation_recommendations(*_args, **_kwargs) -> list[str]:
    """Return mitigation recommendations for the provided risk context."""
    return list(DEFAULT_MITIGATIONS)