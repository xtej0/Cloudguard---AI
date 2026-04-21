from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


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
    impact_hint: str | None = None
    reason: str = Field(
        ...,
        json_schema_extra={"example": "Selected as the highest-scoring reachable compromise candidate."},
    )


class MitigationItem(BaseModel):
    title: str
    recommendation: str
    severity: str
    priority: str
    reason: str


class IntegratedAnalysisResponse(BaseModel):
    asset_name: str = Field(..., json_schema_extra={"example": "Web Server VM"})
    current_risk: CurrentRiskSummary
    candidate_next_hops: list[CandidateNextHop] = Field(default_factory=list)
    predicted_next_target: PredictedNextTarget | None = None
    feature_importance: list[dict[str, Any]] = Field(default_factory=list)
    mitigations: list[MitigationItem] = Field(default_factory=list)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "asset_name": "Web Server VM",
                "current_risk": {
                    "risk_score": 72.4,
                    "risk_level": "HIGH",
                    "explanation": "Internet exposure and weak IAM increase risk.",
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
                            "probabilities": {"HIGH": 0.78, "MEDIUM": 0.18, "LOW": 0.04},
                        },
                        "combined_score": 0.81,
                    }
                ],
                "predicted_next_target": {
                    "asset_name": "Application Server VM",
                    "asset_type": "VM",
                    "predicted_label": "HIGH",
                    "confidence": 0.78,
                    "combined_score": 0.81,
                    "reason": "High privilege escalation potential",
                },
                "feature_importance": [
                    {"feature": "exposure_score", "impact": 0.31, "direction": "increase"}
                ],
                "mitigations": [
                    {
                        "title": "Restrict Internet Exposure",
                        "recommendation": "Restrict inbound traffic and remove unnecessary public network exposure.",
                        "severity": "HIGH",
                        "priority": "P1",
                        "reason": "Asset is internet-exposed, increasing direct attack surface.",
                    }
                ],
            }
        }
    )
