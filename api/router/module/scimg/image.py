import asyncio
from time import perf_counter
from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse
from api.middleware.auth import get_current_user
from api.middleware.limiter import RateLimitedRoute
from api.middleware.quota import ScanQuota
from api.router.runtime import run_scan
from api.router.module.scimg.schema.map_error import ErrorResponse
from api.router.module.scimg.schema.map_result import AnalyzeResponse, ScanResponse, TargetResponse
from plugins.scimg import run_engine
from scamLens import config

router = APIRouter(route_class=RateLimitedRoute, tags=["scimg"])
_semaphore = asyncio.Semaphore(config["rate_limit"]["max_concurrent_scans"])

def _target(scan: dict) -> dict:
    meta = scan["meta"]
    return {
        "identity": {
            "name": meta["image_name"],
            "size_bytes": meta["size_bytes"],
            "sha256": meta["sha256"],
        },
        "image": {
            "width": meta["width"],
            "height": meta["height"],
            "format": meta["format"],
        },
    }

@router.post(
    "/analyze/image",
    response_model=AnalyzeResponse,
    responses={
        400: {"model": ErrorResponse, "description": "Imagem inválida ou não analisável"},
        401: {"description": "Limite anônimo atingido"},
        413: {"description": "Arquivo excede o limite de tamanho"},
        415: {"model": ErrorResponse, "description": "Formato não suportado"},
        429: {"description": "Rate limit ou cota diária excedida"},
        503: {"description": "Servidor ocupado"},
    },
)
async def analyze_image(request: Request, file: UploadFile = File(...)):
    start = perf_counter()
    ip = request.client.host if request.client else "unknown"
    user = None
    try:
        user = get_current_user(request)
    except HTTPException as exc:
        if exc.status_code != 401:
            raise

    limit = int(config["scimg"]["scanner"]["max_file_size_bytes"])
    try:
        data = await file.read(limit + 1)
        if len(data) > limit:
            return JSONResponse(status_code=413, content={
                "status": "error",
                "error": {"type": "size_exceeded", "message": f"Imagem excede {limit} bytes"},
            })
        if not data:
            return JSONResponse(status_code=400, content={
                "status": "error",
                "error": {"type": "empty_input", "message": "Imagem vazia"},
            })
        if _semaphore.locked():
            return JSONResponse(status_code=503, content={"error": "servidor ocupado, tente novamente"})

        filename = (file.filename or "image").replace("\\", "/").rsplit("/", 1)[-1] or "image"
        async with _semaphore:
            quota = ScanQuota(user, ip, "scimg")
            if quota_error := quota.reserve():
                return quota_error
            with quota:
                scan = await run_scan(quota, run_engine, data, file_hint=filename)
                if scan.get("status") == "error":
                    code = scan.get("error", {}).get("type")
                    status_code = 415 if code == "unsupported_format" else 413 if code == "size_exceeded" else 400
                    return JSONResponse(status_code=status_code, content=scan)

                scan["meta"]["scan_time_s"] = round(perf_counter() - start, 4)
                request.state.scan_id = scan["meta"]["scan_id"]
                result = AnalyzeResponse(
                    scan=ScanResponse(**scan),
                    target=TargetResponse(**_target(scan)),
                )
                quota.completed = True
                return result
    finally:
        await file.close()
