from fastapi import APIRouter

router = APIRouter()

@router.get("/attack-paths")
def get_attack_paths():
    return {"paths": []}