from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse
from .schema.map_result import ScanResponse, ScansListResponse, AnalyzeResponse, TargetResponse
from providers.database.repository import list_scans, get_scan

from api.middleware.limiter import RateLimitedRoute

router = APIRouter(route_class=RateLimitedRoute)

@router.get(
    "/scans",
    response_model=ScansListResponse,
)
async def get_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0)
):
    scans = list_scans(limit=limit, offset=offset)
    return {
        "status": "ok",
        "total": len(scans),
        "scans": scans
    }

@router.get("/scans/{identifier}", response_model=AnalyzeResponse)
async def get_scan_by_identifier(identifier: str):
    result = get_scan(identifier)
    if not result:
        return JSONResponse(status_code=404, content={
            "status": "error",
            "message": "Scan não encontrado"
        })
    scan, target = result
    return AnalyzeResponse(scan=ScanResponse(**scan), target=TargetResponse(**target))
