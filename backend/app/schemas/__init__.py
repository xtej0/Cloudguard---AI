from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict


class CytoscapeNodeData(BaseModel):
    id: str
    label: str
    type: str


class CytoscapeEdgeData(BaseModel):
    source: str
    target: str
    label: str


class CytoscapeNode(BaseModel):
    data: CytoscapeNodeData


class CytoscapeEdge(BaseModel):
    data: CytoscapeEdgeData


class GraphData(BaseModel):
    nodes: List[CytoscapeNode]
    edges: List[CytoscapeEdge]


class RiskData(BaseModel):
    top_assets: List[Dict[str, Any]]


class PredictionData(BaseModel):
    next_targets: List[Dict[str, Any]]


class FinalResponse(BaseModel):
    version: Optional[str] = "v1"
    graph: GraphData
    risk: RiskData
    prediction: PredictionData
    summary: Dict[str, Any]
    mitigations: List[str]

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "version": "v1",
                "graph": {
                    "nodes": [
                        {"data": {"id": "Internet", "label": "Internet", "type": "asset"}},
                        {"data": {"id": "Web Server VM", "label": "Web Server VM", "type": "asset"}},
                    ],
                    "edges": [
                        {
                            "data": {
                                "source": "Internet",
                                "target": "Web Server VM",
                                "label": "EXPOSED_TO",
                            }
                        }
                    ],
                },
                "risk": {"top_assets": []},
                "prediction": {"next_targets": []},
                "summary": {
                    "start_asset": "Internet",
                    "target_asset": "Database Server",
                    "message": "No attack path found",
                    "generated_at": "2026-04-10T12:00:00+00:00",
                },
                "mitigations": [
                    "Restrict public exposure",
                    "Apply least privilege IAM policies",
                    "Patch critical vulnerabilities",
                ],
            }
        }
    )


class RootResponse(BaseModel):
    message: str

    model_config = ConfigDict(
        json_schema_extra={"example": {"message": "CloudGuard AI backend running"}}
    )


class HealthResponse(BaseModel):
    status: str

    model_config = ConfigDict(
        json_schema_extra={"example": {"status": "ok"}}
    )


from app.schemas.prediction import PredictionRequest, PredictionResponse

__all__ = [
    "CytoscapeNodeData",
    "CytoscapeEdgeData",
    "CytoscapeNode",
    "CytoscapeEdge",
    "GraphData",
    "RiskData",
    "PredictionData",
    "FinalResponse",
    "RootResponse",
    "HealthResponse",
    "PredictionRequest",
    "PredictionResponse",
]
