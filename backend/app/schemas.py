from pydantic import BaseModel
from typing import List, Dict, Any, Optional

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