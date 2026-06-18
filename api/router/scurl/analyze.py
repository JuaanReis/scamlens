import asyncio
from functools import partial
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from time import perf_counter
from api.limiter import limiter
from api.router.scurl.schema.map_error import ErrorResponse  
from plugins.scurl import run_engine
from providers.database.repository import save_scan
from scamLens import config
from providers.database.usage import is_usage_exceeded, increment_usage, PLAN_LIMITS
from providers.database.quota import is_quota_exceeded, increment_anonymous_count
from plugins.scurl import config as config_scurl
from api.router.scurl.schema.map_result import (
    AnalyzeRequest,
    AnalyzeResponse,
    ScanResponse,
    TargetResponse
)

_rate_enabled = config.get("rate_limit", {}).get("enabled", False)
_rpm = config.get("rate_limit", {}).get("requests_per_minute", 10)
_limit_string = f"{_rpm}/minute" if _rate_enabled else "99999/minute"
router = APIRouter()

MAX_CONCURRENT_SCANS = 20
_semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)

@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        422: {"description": "URL inválida"},
        429: {"description": "Rate limit excedido"},
        503: {"description": "Servidor ocupado"},
    }
)
@limiter.limit(_limit_string)
async def analyze_url(request: Request, body: AnalyzeRequest):
    start = perf_counter()
    user_id = None
    ip = request.client.host
    user = None

    if len(str(body.url)) > 100:
        return JSONResponse(
            status_code=422,
            content={"error": "URL excede o limite de 100 caracteres"}
        )

    try:
        from api.middleware.auth import get_current_user
        user = get_current_user(request)
        user_id = user["id"]
        is_admin = user.get("is_admin", False)
    except:
        pass

    if user_id is None:
        if is_quota_exceeded(ip):
            return JSONResponse(
                status_code=401,
                content={
                    "error": "limite de scans anônimos atingido",
                    "detail": "Crie uma conta para continuar usando o scamLens."
                }
            )
    else:
        if is_usage_exceeded(user_id, "scurl", user["plan_name"], is_admin=is_admin):
            limit = PLAN_LIMITS.get(user["plan_name"])
            return JSONResponse(
                status_code=429,
                content={
                    "error": "limite diário atingido",
                    "detail": f"Seu plano {user['plan_label']} permite {limit} scans por dia. Faça upgrade para continuar."
                }
            )

    if _semaphore.locked():
        return JSONResponse(status_code=503, content={"error": "servidor ocupado, tente novamente"})

    scanner_config = config_scurl.get("scanner", {})
    async with _semaphore:
        loop = asyncio.get_running_loop()
        scan, target = await loop.run_in_executor(
            None, partial(
                run_engine, str(body.url),
                use_cache=body.use_cache,
                timeout=scanner_config.get("timeout", 5.0),
                processors=scanner_config.get("threads", 2),
                k=scanner_config.get("k", 5),
                retries=scanner_config.get("retries", 3)
            )
        )

    if "meta" in scan:
        scan["meta"]["scan_time_s"] = round(perf_counter() - start, 3)

    if scan.get("status") == "error":
        return JSONResponse(status_code=400, content=scan)

    if user_id is None:
        increment_anonymous_count(ip)
    else:
        increment_usage(user_id, "scurl")

    try:
        save_scan(scan, target, user_id=user_id)
    except Exception as e:
        print(f"WARN save_scan failed: {e}")

    return AnalyzeResponse(scan=ScanResponse(**scan), target=TargetResponse(**target))