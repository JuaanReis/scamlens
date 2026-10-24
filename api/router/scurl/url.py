from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import JSONResponse
from time import perf_counter
from api.router.scurl.schema.map_error import ErrorResponse
from plugins.scurl import run_engine
from scamLens import config
from providers.database.repository import save_scan
from api.router.scurl.runtime import scan_semaphore as _semaphore
from api.router.scurl.schema.map_result import (
    AnalyzeRequest,
    AnalyzeResponse,
    ScanResponse,
    TargetResponse
)

from api.middleware.limiter import RateLimitedRoute
from api.middleware.quota import ScanQuota
from api.router.runtime import run_scan

router = APIRouter(route_class=RateLimitedRoute)

@router.post(
    "/analyze/url",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        422: {"description": "URL inválida"},
        429: {"description": "Rate limit excedido"},
        503: {"description": "Servidor ocupado"},
    }
)
async def analyze_url(request: Request, body: AnalyzeRequest):
    start = perf_counter()
    user_id = None
    ip = request.client.host if request.client else "unknown"
    user = None

    max_length = config["scurl"]["security"]["max_url_length"]
    if len(str(body.url)) > max_length:
        return JSONResponse(
            status_code=422,
            content={"error": f"URL excede o limite de {max_length} caracteres"}
        )

    try:
        from api.middleware.auth import get_current_user
        user = get_current_user(request)
        user_id = user["id"]
    except HTTPException:
        pass

    if _semaphore.locked():
        return JSONResponse(status_code=503, content={"error": "servidor ocupado, tente novamente"})

    scanner_config = config["scurl"]["scanner"]
    async with _semaphore:
        quota = ScanQuota(user, ip, "scurl")
        if error := quota.reserve():
            return error
        with quota:
            scan, target = await run_scan(
                quota, run_engine, str(body.url), use_cache=body.use_cache,
                timeout=scanner_config["timeout"], processors=scanner_config["threads"],
                k=scanner_config["k"], retries=scanner_config["retries"],
            )
            if "meta" in scan:
                scan["meta"]["scan_time_s"] = round(perf_counter() - start, 3)
                request.state.scan_id = scan["meta"].get("scan_id")
            if scan.get("status") == "error":
                return JSONResponse(status_code=400, content=scan)
            result = AnalyzeResponse(scan=ScanResponse(**scan), target=TargetResponse(**target))
            try:
                save_scan(scan, target, user_id=user_id)
            except Exception as e:
                print(f"WARN save_scan failed: {e}")
            quota.completed = True
            return result
