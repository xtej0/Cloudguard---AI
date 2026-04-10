import logging
import time

from fastapi import APIRouter, HTTPException

from app.ml_engine import predict_compromise
from app.schemas.prediction import PredictionRequest, PredictionResponse

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post(
    "/predict-compromise",
    response_model=PredictionResponse,
    summary="Predict compromise risk level",
    description="Predicts LOW, MEDIUM, or HIGH compromise risk using the trained ML model.",
)
def predict_compromise_risk(payload: PredictionRequest) -> PredictionResponse:
    """Predict compromise risk from structured asset posture features.

    Example request:
    {
      "asset_type": "Database Server",
      "internet_exposed": 1,
      "public_access": 1,
      "has_critical_data": 1,
      "weak_iam": 1,
      "lateral_movement_possible": 1,
      "privilege_escalation_possible": 1,
      "open_port_count": 14,
      "vulnerability_count": 22,
      "critical_vulnerability_count": 6,
      "misconfiguration_count": 9,
      "attack_path_count": 4,
      "shortest_path_length": 2,
      "exposure_score": 0.82,
      "identity_risk_score": 0.73,
      "network_risk_score": 0.69
    }

    Example response:
    {
      "predicted_label": "HIGH",
      "confidence": 0.87,
      "probabilities": {
        "HIGH": 0.87,
        "MEDIUM": 0.10,
        "LOW": 0.03
      },
      "feature_importance": [
        {
          "feature": "vulnerability_count",
          "impact": 0.23,
          "direction": "increase"
        }
      ]
    }
    """
    start_time = time.time()
    logger.info("Request started: /predict-compromise")
    try:
        payload_dict = payload.model_dump()
        result = predict_compromise(payload_dict)
        if result.get("error"):
            logger.error("Prediction engine returned an error: %s", result.get("error"))
            raise HTTPException(
                status_code=500,
                detail="Prediction failed due to an internal model processing error.",
            )
        return PredictionResponse(**result)
    except HTTPException:
        logger.exception("Request failed: /predict-compromise")
        raise
    except Exception:
        logger.exception("Unexpected error while processing /predict-compromise")
        raise HTTPException(
            status_code=500,
            detail="Prediction request failed due to an unexpected server error.",
        )
    finally:
        end_time = time.time()
        logger.info(f"Execution time: {end_time - start_time:.4f} seconds")
