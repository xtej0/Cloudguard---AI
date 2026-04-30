from __future__ import annotations

from app.mitigation_engine import generate_mitigations
from app.services.mitigation_service import get_mitigation_recommendations


def _titles(items: list[dict]) -> set[str]:
    return {item.get("title", "") for item in items}


def _find_by_title(items: list[dict], title: str) -> dict:
    return next(item for item in items if item.get("title") == title)


def test_internet_exposed_returns_exposure_mitigation():
    results = generate_mitigations({"internet_exposed": 1})

    assert "Restrict Internet Exposure" in _titles(results)
    item = _find_by_title(results, "Restrict Internet Exposure")
    assert item["severity"] == "HIGH"
    assert item["priority"] == "P1"


def test_weak_iam_returns_iam_mitigation():
    results = generate_mitigations({"weak_iam": 1})

    assert "Strengthen IAM Controls" in _titles(results)
    item = _find_by_title(results, "Strengthen IAM Controls")
    assert item["severity"] == "HIGH"
    assert item["priority"] == "P1"


def test_critical_vulnerability_count_returns_patching_recommendation():
    results = generate_mitigations({"critical_vulnerability_count": 2, "vulnerability_count": 8})
    titles = _titles(results)

    assert "Patch Critical Vulnerabilities" in titles
    assert "Review Vulnerability Management" not in titles


def test_critical_data_and_public_access_return_both_recommendations():
    results = generate_mitigations({"has_critical_data": 1, "public_access": 1})
    titles = _titles(results)

    assert "Protect Critical Data" in titles
    assert "Remove Public Access" in titles


def test_multiple_high_risk_flags_adds_combined_recommendation():
    results = generate_mitigations(
        {
            "internet_exposed": 1,
            "weak_iam": 1,
            "critical_vulnerability_count": 1,
        }
    )

    titles = [item.get("title") for item in results]
    assert "Immediate Containment and Security Review" in titles
    assert len(titles) == len(set(titles))


def test_no_issues_returns_empty_list():
    assert generate_mitigations({}) == []


def test_mitigation_service_translates_risk_asset_context():
    results = get_mitigation_recommendations(
        asset={
            "asset_name": "Database Server",
            "node_type": "Database",
            "risk_level": "HIGH",
            "contributing_factors": [
                "High vulnerability severity on this asset",
                "1 distinct attack path(s) from likely entry points",
            ],
            "attack_path_details": {"attack_path_count": 1, "shortest_attack_path_length": 3},
        }
    )

    titles = _titles(results)
    assert "Patch Critical Vulnerabilities" in titles
    assert "Protect Critical Data" in titles
    assert all({"title", "recommendation", "severity", "priority", "reason"}.issubset(item.keys()) for item in results)
