from __future__ import annotations

import logging
import re
import time

from fastapi import APIRouter, HTTPException
from neo4j.exceptions import AuthError, Neo4jError, ServiceUnavailable

from app.integrated_analysis import get_integrated_asset_analysis
from app.schemas.integrated_analysis import IntegratedAnalysisResponse


router = APIRouter()
logger = logging.getLogger(__name__)
ASSET_NAME_PATTERN = re.compile(r"^[A-Za-z0-9 _.-]+$")


def _validated_asset_name(asset_name: str) -> str:
    """Validate and normalize an asset name path parameter."""
    value = str(asset_name).strip() if asset_name is not None else ""
    if not value or len(value) > 120 or not ASSET_NAME_PATTERN.match(value):
        raise HTTPException(
            status_code=400,
            detail=(
                f"Invalid asset name '{value}'. "
                "Only letters, numbers, spaces, '.', '-', and '_' are allowed."
            ),
        )
    return value


@router.get(
    "/asset-analysis/{asset_name}",
    response_model=IntegratedAnalysisResponse,
    summary="Get integrated current risk and next-compromise target analysis for an asset",
    description="Combines current risk, candidate next hops, and predicted next target for a given asset.",
)
def get_asset_analysis(asset_name: str):
    """Return integrated risk and next-target analysis for a single asset.

    Example request:
    GET /asset-analysis/Web%20Server%20VM

    Example response:
    {
      "asset_name": "Web Server VM",
      "current_risk": {
        "risk_score": 72.4,
        "risk_level": "HIGH",
        "explanation": "Internet exposure and weak IAM increase risk."
      },
      "candidate_next_hops": [
        {
          "asset_name": "Application Server VM",
          "asset_type": "VM",
          "path_length": 1,
          "reachability_score": 1.0,
          "prediction": {
            "predicted_label": "HIGH",
            "confidence": 0.78,
            "probabilities": {"HIGH": 0.78, "MEDIUM": 0.18, "LOW": 0.04}
          },
          "combined_score": 0.81
        }
      ],
      "predicted_next_target": {
        "asset_name": "Application Server VM",
        "asset_type": "VM",
        "predicted_label": "HIGH",
        "confidence": 0.78,
        "combined_score": 0.81,
        "reason": "Selected as the highest-scoring reachable compromise candidate."
      },
      "feature_importance": []
    }
    """
    start_time = time.time()
    logger.info("Request started: /asset-analysis/{asset_name}")
    try:
        validated_asset = _validated_asset_name(asset_name)
        return get_integrated_asset_analysis(validated_asset)
    except LookupError as exc:
        logger.exception("Asset lookup failed: /asset-analysis/{asset_name}")
        raise HTTPException(status_code=404, detail=str(exc))
    except HTTPException:
        logger.exception("Request failed: /asset-analysis/{asset_name}")
        raise
    except (ServiceUnavailable, AuthError, Neo4jError):
        logger.exception("Database error while processing /asset-analysis/{asset_name}")
        raise HTTPException(status_code=500, detail="Database connection error")
    except Exception:
        logger.exception("Unexpected error while processing /asset-analysis/{asset_name}")
        raise HTTPException(status_code=500, detail="Internal server error")
    finally:
        end_time = time.time()
        logger.info(f"Execution time: {end_time - start_time:.4f} seconds")
