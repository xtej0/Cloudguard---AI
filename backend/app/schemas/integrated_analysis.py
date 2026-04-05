from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class PredictionSummary(BaseModel):
    predicted_label: str = Field(..., json_schema_extra={"example": "HIGH"})
    confidence: float = Field(..., ge=0.0, le=1.0, json_schema_extra={"example": 0.78})
    probabilities: dict[str, float] = Field(default_factory=dict)


class CandidateNextHop(BaseModel):
    asset_name: str = Field(..., json_schema_extra={"example": "Application Server VM"})
    asset_type: str = Field(..., json_schema_extra={"example": "VM"})
    path_length: int = Field(..., ge=1, json_schema_extra={"example": 1})
    reachability_score: float = Field(..., ge=0.0, le=1.0, json_schema_extra={"example": 1.0})
    prediction: PredictionSummary
    combined_score: float = Field(..., ge=0.0, le=1.0, json_schema_extra={"example": 0.81})


class CurrentRiskSummary(BaseModel):
    risk_score: float = Field(..., ge=0.0, le=100.0, json_schema_extra={"example": 72.4})
    risk_level: str = Field(..., json_schema_extra={"example": "HIGH"})
    explanation: str = Field(..., json_schema_extra={"example": "Internet exposure and weak IAM increase risk."})


class PredictedNextTarget(BaseModel):
    asset_name: str = Field(..., json_schema_extra={"example": "Application Server VM"})
    asset_type: str = Field(..., json_schema_extra={"example": "VM"})
    predicted_label: str = Field(..., json_schema_extra={"example": "HIGH"})
    confidence: float = Field(..., ge=0.0, le=1.0, json_schema_extra={"example": 0.78})
    combined_score: float = Field(..., ge=0.0, le=1.0, json_schema_extra={"example": 0.81})
    reason: str = Field(
        ...,
        json_schema_extra={"example": "Selected as the highest-scoring reachable compromise candidate."},
    )


class IntegratedAnalysisResponse(BaseModel):
    asset_name: str = Field(..., json_schema_extra={"example": "Web Server VM"})
    current_risk: CurrentRiskSummary
    candidate_next_hops: list[CandidateNextHop] = Field(default_factory=list)
    predicted_next_target: PredictedNextTarget | None = None
    feature_importance: list[dict[str, Any]] = Field(default_factory=list)
