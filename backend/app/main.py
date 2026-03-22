from fastapi import FastAPI
from app.routes.attack_paths import router as attack_risk_router

app = FastAPI(
    title="CloudGuard AI",
    description="Attack Path Prediction & Risk Scoring System",
    version="1.0"
)

app.include_router(attack_risk_router)

@app.get("/")
def root():
    return {"message": "CloudGuard AI backend running"}