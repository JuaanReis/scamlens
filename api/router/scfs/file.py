import asyncio
import logging
import sqlite3
from time import perf_counter
from fastapi import APIRouter, Request, UploadFile, File, HTTPException
from fastapi.responses import JSONResponse
from api.middleware.auth import get_current_user
from api.router.scfs.schema.map_error import ErrorResponse
from api.router.scfs.schema.map_result import AnalyzeResponse, ScanResponse, TargetResponse
from plugins.scfs import run_engine, Settings
from providers.database.history import save_module_scan
from scamLens import config

from api.middleware.limiter import RateLimitedRoute
from api.middleware.quota import ScanQuota
from api.router.runtime import run_scan

router = APIRouter(route_class=RateLimitedRoute, tags=["scfs"])
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
    ip = request.client.host if request.client else "unknown"

    try:
        user = get_current_user(request)
    except HTTPException:
        pass

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

        quota = ScanQuota(user, ip, "scfs")
        if error := quota.reserve():
            return error
        with quota:
            filename = (file.filename or "sample").replace("\\", "/").rsplit("/", 1)[-1] or "sample"
            scan, target = await run_scan(quota, run_engine, data, name=filename, settings=settings)
            scan["meta"]["scan_time_s"] = round(perf_counter() - start, 3)
            request.state.scan_id = scan["meta"]["scan_id"]
            if scan.get("status") == "error":
                status_code = 415 if scan["error"]["code"] == "unsupported_format" else 400
                return JSONResponse(status_code=status_code, content=scan)
            result = AnalyzeResponse(scan=ScanResponse(**scan), target=TargetResponse(**target))
            try:
                save_module_scan("scfs", result.scan.model_dump(), result.target.model_dump(),
                                 user_id=user["id"] if user else None)
            except sqlite3.Error:
                logging.getLogger(__name__).exception("Não foi possível salvar o histórico SCFS")
                return JSONResponse(status_code=503, content={"error": "não foi possível salvar a análise; tente novamente"})
            quota.completed = True
            return result
