from fastapi import APIRouter, HTTPException

from app.ml_engine import predict_compromise
from app.schemas.prediction import PredictionRequest, PredictionResponse

router = APIRouter()


@router.post(
    "/predict-compromise",
    response_model=PredictionResponse,
    summary="Predict compromise risk level",
    description="Predicts LOW, MEDIUM, or HIGH risk using ML model",
)
def predict_compromise_risk(payload: PredictionRequest) -> PredictionResponse:
    try:
        payload_dict = payload.model_dump()
        result = predict_compromise(payload_dict)
        return PredictionResponse(**result)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Prediction failed: {str(exc)}")
