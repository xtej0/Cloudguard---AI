from fastapi import FastAPI
from app.routes.attack_paths import router as attack_risk_router
<<<<<<< HEAD
from app.routes.prediction import router as prediction_router
=======
from app.routes.integrated_analysis import router as integrated_analysis_router
>>>>>>> 9c7f216 (Integrate attack graph and ML next-target prediction)

app = FastAPI(
    title="CloudGuard AI",
    description="Cloud Attack Path & Risk Prediction API",
    version="1.0"
)

app.include_router(attack_risk_router)
<<<<<<< HEAD
app.include_router(prediction_router, tags=["Prediction"])
=======
app.include_router(integrated_analysis_router)
>>>>>>> 9c7f216 (Integrate attack graph and ML next-target prediction)

@app.get("/")
def root():
    return {"message": "CloudGuard AI backend running"}