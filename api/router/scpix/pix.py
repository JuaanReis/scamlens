"""Router Pix: reutiliza autenticação, cota e rate-limit do ScamLens."""
import asyncio
import logging
import sqlite3
from functools import partial
from time import perf_counter
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from api.middleware.auth import get_current_user
from api.router.scpix.schema.map_result import (PixAnalyzeRequest, AnalyzeResponse,
                                                ScanResponse, TargetResponse)
from plugins.scpix import run_engine, Settings
from providers.database.usage import is_usage_exceeded, increment_usage, PLAN_LIMITS
from providers.database.quota import is_quota_exceeded, increment_anonymous_count
from providers.database.history import save_module_scan
from scamLens import config

router = APIRouter(tags=["scpix"])
_semaphore = asyncio.Semaphore(config["rate_limit"]["max_concurrent_scans"])


@router.post(
    "/analyze/pix",
    response_model=AnalyzeResponse,
    responses={
        400: {"description": "BR Code inválido"},
        401: {"description": "Limite de scans anônimos atingido"},
        413: {"description": "Payload excede limite"},
        429: {"description": "Rate limit ou limite diário excedido"},
        503: {"description": "Servidor ocupado"},
    },
)
async def analyze_pix(request: Request, input: PixAnalyzeRequest):
    start = perf_counter()
    user = None
    ip = request.client.host if request.client else "unknown"
    try:
        user = get_current_user(request)
    except HTTPException:
        pass

    if user is None:
        if is_quota_exceeded(ip):
            return JSONResponse(status_code=401, content={
                "error": "limite de scans anônimos atingido",
                "detail": "Crie uma conta para continuar usando o ScamLens.",
            })
    elif is_usage_exceeded(user["id"], "scpix", user["plan_name"], is_admin=user.get("is_admin", False)):
        limit = PLAN_LIMITS.get(user["plan_name"])
        return JSONResponse(status_code=429, content={
            "error": "limite diário atingido",
            "detail": f"Seu plano {user['plan_label']} permite {limit} scans por dia.",
        })

    if _semaphore.locked():
        return JSONResponse(status_code=503, content={"error": "servidor ocupado, tente novamente"})

    async with _semaphore:
        scanner = Settings()
        if len(input.payload.encode("utf-8")) > scanner.max_payload_bytes:
            return JSONResponse(status_code=413, content={"error": "payload excede limite de bytes"})
        loop = asyncio.get_running_loop()
        scan, target = await loop.run_in_executor(
            None,
            partial(run_engine, input.payload, settings=scanner, expected=input.expected),
        )

    request.state.scan_id = scan["meta"]["scan_id"]
    if scan["status"] == "error":
        status = 413 if scan["error"]["code"] == "payload_too_large" else 400
        return JSONResponse(status_code=status, content=scan)

    scan["meta"]["scan_time_s"] = round(perf_counter() - start, 4)
    result = AnalyzeResponse(scan=ScanResponse(**scan), target=TargetResponse(**target))
    try:
        save_module_scan("scpix", result.scan.model_dump(), result.target.model_dump(), user_id=user["id"] if user else None)
    except sqlite3.Error:
        logging.getLogger(__name__).exception("Não foi possível salvar o histórico SCPIX")
        return JSONResponse(status_code=503, content={"error": "não foi possível salvar a análise; tente novamente"})

    if user is None:
        increment_anonymous_count(ip)
    else:
        increment_usage(user["id"], "scpix")
    return result
