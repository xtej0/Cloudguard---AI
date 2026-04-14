import logging
import time

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from app.routes.attack_paths import router as attack_risk_router
from app.routes.prediction import router as prediction_router
from app.routes.integrated_analysis import router as integrated_analysis_router
from app.schemas import HealthResponse, RootResponse

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CloudGuard AI",
    description="Cloud Attack Path & Risk Prediction API",
    version="1.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def request_timing_logger(request: Request, call_next):
    """Log request method, path, and execution time for every HTTP call."""
    start_time = time.time()
    response = await call_next(request)
    end_time = time.time()
    logger.info(
        "method=%s path=%s execution_time=%.4fs",
        request.method,
        request.url.path,
        end_time - start_time,
    )
    return response

app.include_router(attack_risk_router)
app.include_router(prediction_router, tags=["Prediction"])
app.include_router(integrated_analysis_router)


@app.get(
    "/",
    response_model=RootResponse,
    summary="Backend status message",
    description="Returns a simple status message to confirm the backend is reachable.",
)
def root() -> RootResponse:
    return {"message": "CloudGuard AI backend running"}


@app.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Returns service health status for monitoring and readiness checks.",
)
def health() -> HealthResponse:
    return {"status": "ok"}