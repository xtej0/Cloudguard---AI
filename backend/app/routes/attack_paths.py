from __future__ import annotations

import logging
import time

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse

from app.builders.response_builder import (
    build_all_paths_response,
    build_attack_path_response,
    build_attack_risk_response,
    build_error_response,
    build_risk_score_response,
    build_single_asset_risk_response,
)
from app.schemas import FinalResponse
from app.services.attack_graph_service import (
    get_all_attack_paths,
    get_asset_existence,
    get_shortest_attack_path,
)
from app.services.attack_risk_service import get_attack_risk_summary
from app.services.risk_service import calculate_risk_score, get_top_asset_risk_scores

router = APIRouter()

logging.basicConfig(level=logging.INFO)


@router.get("/attack-path", response_model=FinalResponse)
def get_attack_path(start: str, target: str):
    """Return shortest attack path between start and target assets."""
    start_time = time.time()
    path = get_shortest_attack_path(start=start, target=target)
    start_exists, target_exists = get_asset_existence(start, target)

    execution_time = time.time() - start_time
    logging.info(f"Shortest attack path query executed in {execution_time:.4f} seconds")

    if not path:
        return build_attack_path_response(
            [],
            [],
            start=start,
            target=target,
            start_exists=start_exists,
            target_exists=target_exists,
        )

    return build_attack_path_response(
        path.get("nodes", []),
        path.get("relationships", []),
        start=start,
        target=target,
        start_exists=start_exists,
        target_exists=target_exists,
    )


@router.get("/all-paths", response_model=FinalResponse)
def get_all_paths(start: str, target: str):
    """Return all attack paths between start and target assets."""
    start_time = time.time()
    paths = get_all_attack_paths(start=start, target=target)
    start_exists, target_exists = get_asset_existence(start, target)

    execution_time = time.time() - start_time
    logging.info(f"All attack paths query executed in {execution_time:.4f} seconds")

    return build_all_paths_response(
        paths,
        start=start,
        target=target,
        start_exists=start_exists,
        target_exists=target_exists,
    )


@router.get(
    "/attack-risk-summary",
    response_model=FinalResponse,
    summary="Get attack risk summary between assets",
    description="Returns a risk summary for attack paths from the start asset to the target asset.",
)
def attack_risk_summary(start: str, target: str):
    """Return attack risk summary, or error when path is unavailable."""
    try:
        start_exists, target_exists = get_asset_existence(start, target)
        summary = get_attack_risk_summary(start=start, target=target)
        if isinstance(summary, dict) and "error" in summary:
            return JSONResponse(content=build_error_response(summary["error"]))

        return build_attack_risk_response(
            summary,
            start=start,
            target=target,
            start_exists=start_exists,
            target_exists=target_exists,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch attack risk summary: {str(exc)}")


@router.get(
    "/risk-score",
    response_model=FinalResponse,
    summary="Get top asset risk scores",
    description="Returns all assets ranked by risk score, including explanations, contributing factors, and attack path details.",
)
def get_top_risk_scores():
    """Return all assets ranked by risk score."""
    try:
        top_assets = get_top_asset_risk_scores()
        return build_risk_score_response(top_assets)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch asset risk scores: {str(exc)}")


@router.get(
    "/risk-score/{asset_name}",
    response_model=FinalResponse,
    summary="Get risk score for one asset",
    description="Returns risk score details for a single asset, including risk level and attack path details.",
)
def get_asset_risk_score(asset_name: str):
    """Return risk score details for a single asset."""
    try:
        risk_data = calculate_risk_score(asset_name)
        raw_inputs = risk_data.get("raw_inputs", {})

        asset_data = {
            "asset_name": risk_data.get("asset_name", asset_name),
            "risk_score": risk_data.get("risk_score"),
            "risk_level": risk_data.get("risk_level"),
            "attack_path_details": {
                "attack_path_count": raw_inputs.get("attack_path_count"),
                "shortest_attack_path_length": raw_inputs.get("shortest_attack_path_length"),
            },
        }
        return build_single_asset_risk_response(asset_data)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to fetch risk score for asset '{asset_name}': {str(exc)}")