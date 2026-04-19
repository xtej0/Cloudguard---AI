from __future__ import annotations

import logging
import re
import time

from fastapi import APIRouter, HTTPException
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable

from app.builders.response_builder import (
    build_attack_risk_response,
    build_risk_score_response,
    build_single_asset_risk_response,
)
from app.schemas import FinalResponse
from app.services.attack_graph_service import (
    generate_attack_path,
    generate_full_graph,
    get_asset_existence,
)
from app.services.attack_risk_service import get_attack_risk_summary
from app.services.risk_service import get_single_asset_risk_data, get_top_asset_risk_scores

router = APIRouter()
logger = logging.getLogger(__name__)
ASSET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9 _.-]+$")


def _validated_asset_name(asset_name: str, field_name: str) -> str:
    """Validate and normalize an asset identifier from request input."""
    value = str(asset_name).strip() if asset_name is not None else ""
    if not value or len(value) > 120 or not ASSET_NAME_PATTERN.match(value):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid {field_name} name '{value}'. "
                "Only letters, numbers, spaces, '.', '-', and '_' are allowed."
            ),
        )
    return value


def _mark_no_path(response: dict) -> dict:
    """Keep schema-compatible no-path response while exposing explicit signal."""
    summary = response.setdefault("summary", {})
    summary["message"] = "No attack path found"
    summary["paths"] = []
    return response


@router.get(
    "/attack-path",
    response_model=FinalResponse,
    summary="Get shortest attack path",
    description="Returns the shortest directed attack path between two assets and a unified summary payload.",
)
def attack_path(start: str, target: str):
    """Return shortest attack path between start and target assets.

    Example request:
    GET /attack-path?start=Internet&target=Database%20Server

    Example response:
    {
      "version": "v1",
      "graph": {"nodes": [], "edges": []},
      "risk": {"top_assets": []},
      "prediction": {"next_targets": []},
      "summary": {
        "start_asset": "Internet",
        "target_asset": "Database Server",
        "path_length": 0,
        "message": "No attack path found",
        "paths": []
      },
      "mitigations": []
    }
    """
    start_time = time.time()
    logger.info("Request started: /attack-path")
    try:
        validated_start = _validated_asset_name(start, "asset")
        validated_target = _validated_asset_name(target, "asset")

        start_exists, target_exists = get_asset_existence(validated_start, validated_target)

        return generate_attack_path(
            start=validated_start,
            target=validated_target,
            start_exists=start_exists,
            target_exists=target_exists,
        )
    except HTTPException:
        logger.exception("Request failed: /attack-path")
        raise
    except (ServiceUnavailable, AuthError, Neo4jError):
        logger.exception("Database error while processing /attack-path")
        raise HTTPException(status_code=500, detail="Database connection error")
    except Exception:
        logger.exception("Unexpected error while processing /attack-path")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        end_time = time.time()
        logger.info(f"Execution time: {end_time - start_time:.4f} seconds")


@router.get(
    "/all-paths",
    response_model=FinalResponse,
    summary="Get all attack paths",
    description="Returns all directed attack paths between two assets in the unified response structure.",
)
def all_paths(start: str, target: str):
    """Return all attack paths between start and target assets.

    Example request:
    GET /all-paths?start=Internet&target=Database%20Server

    Example response:
    {
      "version": "v1",
      "graph": {"nodes": [], "edges": []},
      "risk": {"top_assets": []},
      "prediction": {"next_targets": []},
      "summary": {
        "start_asset": "Internet",
        "target_asset": "Database Server",
        "total_paths": 0,
        "message": "No attack path found",
        "paths": []
      },
      "mitigations": []
    }
    """
    start_time = time.time()
    logger.info("Request started: /all-paths")
    try:
        validated_start = _validated_asset_name(start, "asset")
        validated_target = _validated_asset_name(target, "asset")

        start_exists, target_exists = get_asset_existence(validated_start, validated_target)

        return generate_full_graph(
            start=validated_start,
            target=validated_target,
            start_exists=start_exists,
            target_exists=target_exists,
        )
    except HTTPException:
        logger.exception("Request failed: /all-paths")
        raise
    except (ServiceUnavailable, AuthError, Neo4jError):
        logger.exception("Database error while processing /all-paths")
        raise HTTPException(status_code=500, detail="Database connection error")
    except Exception:
        logger.exception("Unexpected error while processing /all-paths")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        end_time = time.time()
        logger.info(f"Execution time: {end_time - start_time:.4f} seconds")


@router.get(
    "/attack-risk-summary",
    response_model=FinalResponse,
    summary="Get attack risk summary between assets",
    description="Returns a risk summary for attack paths from the start asset to the target asset.",
)
def attack_risk_summary(start: str, target: str):
    """Return attack risk summary between two assets.

    Example request:
    GET /attack-risk-summary?start=Internet&target=Database%20Server

    Example response:
    {
      "version": "v1",
      "graph": {"nodes": [], "edges": []},
      "risk": {"top_assets": []},
      "prediction": {"next_targets": []},
      "summary": {
        "start_asset": "Internet",
        "target_asset": "Database Server",
        "message": "No attack path found",
        "paths": []
      },
      "mitigations": []
    }
    """
    start_time = time.time()
    logger.info("Request started: /attack-risk-summary")
    try:
        validated_start = _validated_asset_name(start, "asset")
        validated_target = _validated_asset_name(target, "asset")

        start_exists, target_exists = get_asset_existence(validated_start, validated_target)
        summary = get_attack_risk_summary(start=validated_start, target=validated_target)
        if isinstance(summary, dict) and "error" in summary:
            error_message = str(summary.get("error") or "")
            if "No attack path found" in error_message:
                response = build_attack_risk_response(
                    summary,
                    start=validated_start,
                    target=validated_target,
                    start_exists=start_exists,
                    target_exists=target_exists,
                )
                return _mark_no_path(response)

        return build_attack_risk_response(
            summary,
            start=validated_start,
            target=validated_target,
            start_exists=start_exists,
            target_exists=target_exists,
        )
    except HTTPException:
        logger.exception("Request failed: /attack-risk-summary")
        raise
    except (ServiceUnavailable, AuthError, Neo4jError):
        logger.exception("Database error while processing /attack-risk-summary")
        raise HTTPException(status_code=500, detail="Database connection error")
    except Exception:
        logger.exception("Unexpected error while processing /attack-risk-summary")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        end_time = time.time()
        logger.info(f"Execution time: {end_time - start_time:.4f} seconds")


@router.get(
    "/risk-score",
    response_model=FinalResponse,
    summary="Get top asset risk scores",
    description="Returns all assets ranked by risk score, including explanations, contributing factors, and attack path details.",
)
def get_top_risk_scores():
    """Return all assets ranked by risk score.

    Example request:
    GET /risk-score

    Example response:
    {
      "version": "v1",
      "graph": {"nodes": [], "edges": []},
      "risk": {
        "top_assets": [
          {
            "asset_name": "Database Server",
            "risk_score": 85.4,
            "risk_level": "CRITICAL"
          }
        ]
      },
      "prediction": {"next_targets": []},
      "summary": {"total_assets": 1},
      "mitigations": []
    }
    """
    start_time = time.time()
    logger.info("Request started: /risk-score")
    try:
        top_assets = get_top_asset_risk_scores()
        return build_risk_score_response(top_assets)
    except HTTPException:
        logger.exception("Request failed: /risk-score")
        raise
    except (ServiceUnavailable, AuthError, Neo4jError):
        logger.exception("Database error while processing /risk-score")
        raise HTTPException(status_code=500, detail="Database connection error")
    except Exception:
        logger.exception("Unexpected error while processing /risk-score")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        end_time = time.time()
        logger.info(f"Execution time: {end_time - start_time:.4f} seconds")


@router.get(
    "/risk-score/{asset_name}",
    response_model=FinalResponse,
    summary="Get risk score for one asset",
    description="Returns risk score details for a single asset, including risk level and attack path details.",
)
def get_asset_risk_score(asset_name: str):
    """Return risk score details for a single asset.

    Example request:
    GET /risk-score/Database%20Server

    Example response:
    {
      "version": "v1",
      "graph": {"nodes": [], "edges": []},
      "risk": {
        "top_assets": [
          {
            "asset_name": "Database Server",
            "risk_score": 82.1,
            "risk_level": "HIGH"
          }
        ]
      },
      "prediction": {"next_targets": []},
      "summary": {
        "target_asset": "Database Server",
        "overall_risk_level": "HIGH"
      },
      "mitigations": []
    }
    """
    start_time = time.time()
    logger.info("Request started: /risk-score/{asset_name}")
    try:
        validated_asset = _validated_asset_name(asset_name, "asset")
        asset_data = get_single_asset_risk_data(validated_asset)
        return build_single_asset_risk_response(asset_data)
    except HTTPException:
        logger.exception("Request failed: /risk-score/{asset_name}")
        raise
    except (ServiceUnavailable, AuthError, Neo4jError):
        logger.exception("Database error while processing /risk-score/{asset_name}")
        raise HTTPException(status_code=500, detail="Database connection error")
    except Exception:
        logger.exception("Unexpected error while processing /risk-score/{asset_name}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        end_time = time.time()
        logger.info(f"Execution time: {end_time - start_time:.4f} seconds")