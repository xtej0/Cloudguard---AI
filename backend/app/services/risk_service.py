from __future__ import annotations

from typing import Any

from risk_engine import compute_risk_score, get_all_asset_risk_scores


def calculate_risk_score(asset_name: str) -> dict[str, Any]:
    """Calculate risk score details for a single asset."""
    return compute_risk_score(asset_name)


def get_top_asset_risk_scores() -> list[dict[str, Any]]:
    """Return ranked risk scores for all assets."""
    return get_all_asset_risk_scores()