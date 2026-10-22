import asyncio
import logging
import sqlite3
from functools import partial
from time import perf_counter
from fastapi import APIRouter, Request, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from api.middleware.auth import get_current_user
from api.router.scfs.schema.map_error import ErrorResponse
from api.router.scfs.schema.map_result import AnalyzeResponse, ScanResponse, TargetResponse
from plugins.scfs import run_engine, Settings
from providers.database.usage import is_usage_exceeded, increment_usage, PLAN_LIMITS
from providers.database.quota import is_quota_exceeded, increment_anonymous_count
from providers.database.history import save_module_scan
from scamLens import config

router = APIRouter(tags=["scfs"])
_semaphore = asyncio.Semaphore(config["rate_limit"]["max_concurrent_scans"])

@router.post(
    "/analyze/file",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"description": "Limite anônimo atingido"},
        413: {"description": "Arquivo excede o limite de tamanho"},
        415: {"model": ErrorResponse, "description": "Formato não suportado"},
        429: {"description": "Rate limit ou limite diário excedido"},
        503: {"description": "Servidor ocupado"},
    }
)
async def analyze_file(request: Request, file: UploadFile = File(...)):
    start = perf_counter()
    user = None
    ip = request.client.host

    try:
        user = get_current_user(request)
    except HTTPException:
        pass

    if user is None:
        if is_quota_exceeded(ip):
            return JSONResponse(status_code=401, content={
                "error": "limite de scans anônimos atingido",
                "detail": "Crie uma conta para continuar usando o scamLens."
            })
        
    elif is_usage_exceeded(user["id"], "scfs", user["plan_name"], is_admin=user.get("is_admin", False)):
        limit = PLAN_LIMITS.get(user["plan_name"])
        return JSONResponse(status_code=429, content={
            "error": "limite diário atingido",
            "detail": f"Seu plano {user['plan_label']} permite {limit} scans por dia. Faça upgrade para continuar."
        })

    if _semaphore.locked():
        return JSONResponse(status_code=503, content={"error": "servidor ocupado, tente novamente"})

    scanner_config = config["scfs"]["scanner"]
    settings = Settings(
        k=scanner_config["k"],
        max_file_bytes=scanner_config["max_file_size_bytes"],
        max_strings=scanner_config["max_strings"],
        score_model=scanner_config["score_model"],
        disabled_rules=tuple(scanner_config["disabled_rules"])
    )

    async with _semaphore:
        data = await file.read(settings.max_file_bytes + 1)
        if len(data) > settings.max_file_bytes:
            return JSONResponse(status_code=413, content={
                "error": f"Arquivo excede o limite de {settings.max_file_bytes} bytes"
            })

        filename = (file.filename or "sample").replace("\\", "/").rsplit("/", 1)[-1] or "sample"
        loop = asyncio.get_running_loop()
        scan, target = await loop.run_in_executor(
            None, partial(run_engine, data, name=filename, settings=settings)
        )

    scan["meta"]["scan_time_s"] = round(perf_counter() - start, 3)
    request.state.scan_id = scan["meta"]["scan_id"]
    if scan.get("status") == "error":
        status_code = 415 if scan["error"]["code"] == "unsupported_format" else 400
        return JSONResponse(status_code=status_code, content=scan)

    result = AnalyzeResponse(scan=ScanResponse(**scan), target=TargetResponse(**target))
    try:
        save_module_scan("scfs", result.scan.model_dump(), result.target.model_dump(), user_id=user["id"] if user else None)
    except sqlite3.Error:
        logging.getLogger(__name__).exception("Não foi possível salvar o histórico SCFS")
        return JSONResponse(status_code=503, content={"error": "não foi possível salvar a análise; tente novamente"})

    if user is None:
        increment_anonymous_count(ip)
    else:
        increment_usage(user["id"], "scfs")
    return result
