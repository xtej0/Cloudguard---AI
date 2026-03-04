from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def root():
    return {"message": "CloudGuard AI Backend Running Successfully"}