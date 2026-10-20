import asyncio
from functools import partial
from fastapi import APIRouter, Request, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from time import perf_counter
from api.router.scurl.schema.map_error import ErrorResponse
from plugins.scurl import run_engine
from providers.database.repository import save_scan
from scamLens import config
from providers.database.usage import is_usage_exceeded, increment_usage, PLAN_LIMITS
from providers.database.quota import is_quota_exceeded, increment_anonymous_count
from api.router.scurl.runtime import scan_semaphore as _semaphore
from api.router.scurl.schema.map_result import (
    AnalyzeResponse,
    ScanResponse,
    TargetResponse
)

router = APIRouter()

@router.post(
    "/analyze/qr",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"description": "Limite anônimo atingido"},
        415: {"description": "Tipo de arquivo não suportado"},
        429: {"description": "Rate limit ou limite diário excedido"},
        503: {"description": "Servidor ocupado"},
    }
)
async def analyze_qr(request: Request, file: UploadFile = File(...)):
    start = perf_counter()
    user_id = None
    ip = request.client.host
    user = None

    try:
        from api.middleware.auth import get_current_user
        user = get_current_user(request)
        user_id = user["id"]
        is_admin = user.get("is_admin", False)
    except HTTPException:
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

    max_size = config["uploads"]["qr_max_bytes"]
    data = await file.read(max_size + 1)
    if len(data) > max_size:
        return JSONResponse(status_code=413, content={"error": f"Arquivo excede o limite de {max_size} bytes"})

    if _semaphore.locked():
        return JSONResponse(status_code=503, content={"error": "servidor ocupado, tente novamente"})

    scanner_config = config["scurl"]["scanner"]
    async with _semaphore:
        loop = asyncio.get_running_loop()
        scan, target = await loop.run_in_executor(
            None, partial(
                run_engine, data,
                use_cache=False,
                timeout=scanner_config["timeout"],
                processors=scanner_config["threads"],
                k=scanner_config["k"],
                retries=scanner_config["retries"]
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
