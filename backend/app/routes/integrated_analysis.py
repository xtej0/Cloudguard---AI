from __future__ import annotations

from fastapi import APIRouter, HTTPException

from app.integrated_analysis import get_integrated_asset_analysis
from app.schemas.integrated_analysis import IntegratedAnalysisResponse


router = APIRouter()


@router.get(
    "/asset-analysis/{asset_name}",
    response_model=IntegratedAnalysisResponse,
    summary="Get integrated current risk and next-compromise target analysis for an asset",
)
def get_asset_analysis(asset_name: str):
    try:
        return get_integrated_asset_analysis(asset_name)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to compute integrated asset analysis: {str(exc)}")
