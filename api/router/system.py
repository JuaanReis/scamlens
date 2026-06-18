from scamLens import __version__
from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

router = APIRouter()
_STATIC = Path(__file__).parent.parent / "static"

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    return (_STATIC / "index.html").read_text(encoding="utf-8")

@router.get("/favicon.ico", include_in_schema=False)
async def favicon_ico():
    return FileResponse(_STATIC / "favicon.png", media_type="image/x-icon")

@router.get("/health")
async def health():
    db_status = "ok"
    try:
        from providers.database.connection import get_connection
        get_connection().execute("SELECT 1")
    except Exception:
        db_status = "error"

    return {
        "status": "ok",
        "version": __version__,
        "datetime": datetime.now(timezone.utc),
        "db": db_status,
    }