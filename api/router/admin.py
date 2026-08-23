from pathlib import Path
from fastapi import APIRouter, Depends, Query, HTTPException
from .schema.admin_schema import ActiveBody, PlanBody, VALID_PLANS
from api.middleware.auth import get_current_admin
from providers.database.connection import get_connection
from providers.database.users import list_users, set_user_active, update_user_plan, get_global_metrics
from providers.database.repository import list_scans
from fastapi.responses import PlainTextResponse
from ..path import _LOG_DIR

router = APIRouter(prefix="/api/admin", tags=["admin"])

def _audit(admin_id: int, action: str, target_user_id: int | None = None, detail: str | None = None) -> None:
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO admin_audit_log (admin_id, action, target_user_id, detail)
        VALUES (?, ?, ?, ?)
        """,
        (admin_id, action, target_user_id, detail),
    )
    conn.commit()

@router.get("/metrics")
def metrics(admin: dict = Depends(get_current_admin)):
    return get_global_metrics()

@router.get("/users")
def get_users(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: dict = Depends(get_current_admin),
):
    _audit(admin["id"], "read_users", detail=f"limit={limit} offset={offset}")
    return {
        "users": list_users(limit=limit, offset=offset)
    }

@router.patch("/users/{user_id}/active")
def toggle_active(user_id: int, body: ActiveBody, admin: dict = Depends(get_current_admin)):
    set_user_active(user_id, body.is_active)
    _audit(admin["id"], "set_active", target_user_id=user_id, detail=str(body.is_active))
    return {
        "ok": True
    }

@router.patch("/users/{user_id}/plan")
def change_plan(user_id: int, body: PlanBody, admin: dict = Depends(get_current_admin)):
    if body.plan_name not in VALID_PLANS:
        raise HTTPException(status_code=400, detail=f"Plano inválido. Use: {VALID_PLANS}")

    update_user_plan(user_id, body.plan_name)
    _audit(admin["id"], "change_plan", target_user_id=user_id, detail=body.plan_name)
    return {
        "ok": True
    }

@router.get("/scans")
def get_all_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: dict = Depends(get_current_admin),
):
    _audit(admin["id"], "read_scans", detail=f"limit={limit} offset={offset}")
    return {
        "scans": list_scans(limit=limit, offset=offset)
    }

@router.get("/request-logs")
def get_logs(
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    admin: dict = Depends(get_current_admin),
):
    _audit(admin["id"], "read_logs", detail=f"limit={limit} offset={offset}")
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset),
    ).fetchall() 
    return [dict(r) for r in rows]

def _safe_log_path(filename: str) -> Path:
    base = _LOG_DIR.resolve()
    candidate = (base / filename).resolve()

    if (
        base not in candidate.parents
        or candidate.suffix.lower() != ".log"
        or not candidate.is_file()
    ):
        raise HTTPException(
            status_code=404,
            detail="log file not found",
        )

    return candidate

@router.get("/logs")
def list_logs(admin=Depends(get_current_admin)):
    _audit(admin["id"], "list_logs")

    files = []
    for f in sorted(_LOG_DIR.glob("*.log")):
        stat = f.stat()
        files.append({
            "name": f.name,
            "size_bytes": stat.st_size,
            "modified_at": stat.st_mtime,
        })
    return {"logs": files}

@router.get("/logs/{filename}")
def read_log(
    filename: str,
    tail: int = Query(500, ge=1, le=10000, description="últimas N linhas"),
    admin=Depends(get_current_admin),
):
    path = _safe_log_path(filename)
    _audit(admin["id"], "read_log", detail=f"file={filename} tail={tail}")

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()[-tail:]

    return PlainTextResponse("".join(lines))