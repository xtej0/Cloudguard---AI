from fastapi import FastAPI
from app.routes.attack_paths import router as attack_risk_router
from app.routes.prediction import router as prediction_router

app = FastAPI(
    title="CloudGuard AI",
    description="Cloud Attack Path & Risk Prediction API",
    version="1.0"
)

app.include_router(attack_risk_router)
app.include_router(prediction_router, tags=["Prediction"])

@app.get("/")
def root():
    return {"message": "CloudGuard AI backend running"}