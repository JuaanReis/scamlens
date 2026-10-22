from fastapi import APIRouter, Depends, HTTPException, Query
from api.middleware.auth import get_current_user
from api.router.schema.history_schema import ScanHistoryResponse
from api.router.scpix.schema.map_result import AnalyzeResponse
from providers.database.history import get_module_scan, list_scan_history

router = APIRouter(tags=["scpix"])


@router.get("/scans", response_model=ScanHistoryResponse)
def get_scans(limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0),
              target_hash: str | None = Query(None, min_length=64, max_length=64),
              user: dict = Depends(get_current_user)):
    owner = None if user.get("is_admin") else user["id"]
    return list_scan_history(module="scpix", user_id=owner, target_hash=target_hash, limit=limit, offset=offset)


@router.get("/scans/{scan_id}", response_model=AnalyzeResponse)
def get_scan(scan_id: str, user: dict = Depends(get_current_user)):
    owner = None if user.get("is_admin") else user["id"]
    result = get_module_scan("scpix", scan_id, user_id=owner)
    if result is None:
        raise HTTPException(status_code=404, detail="Scan não encontrado")
    return result
