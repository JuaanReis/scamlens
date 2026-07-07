from datetime import datetime, timezone
from pathlib import Path
from fastapi import APIRouter, Depends
from fastapi.responses import FileResponse, HTMLResponse

router = APIRouter()
_STATIC = Path(__file__).parent.parent / "static"

_INDEX_HTML: str = (_STATIC / "index.html").read_text(encoding="utf-8")

@router.get("/", response_class=HTMLResponse, include_in_schema=False)
async def index():
    return _INDEX_HTML

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
        "datetime": datetime.now(timezone.utc),
        "db": db_status,
    }

@router.get("/health/version")
async def health_version(admin: dict = Depends(__import__("api.middleware.auth", fromlist=["get_current_admin"]).get_current_admin)):
    from scamLens import __version__
    return {
        "version": __version__
    }