from fastapi import FastAPI
from app.routes.attack_paths import router as attack_risk_router
from app.routes.prediction import router as prediction_router
from app.routes.integrated_analysis import router as integrated_analysis_router

app = FastAPI(
    title="CloudGuard AI",
    description="Cloud Attack Path & Risk Prediction API",
    version="1.0"
)

app.include_router(attack_risk_router)
app.include_router(prediction_router, tags=["Prediction"])
app.include_router(integrated_analysis_router)

@app.get("/")
def root():
    return {"message": "CloudGuard AI backend running"}