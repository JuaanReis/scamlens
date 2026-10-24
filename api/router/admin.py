from pathlib import Path
import json
import re
from typing import Literal
from fastapi import APIRouter, Depends, Query, HTTPException
from .schema.admin_schema import ActiveBody, PlanBody, VALID_PLANS
from api.middleware.auth import get_current_admin
from providers.database.connection import get_connection
from providers.database.users import list_users, set_user_active, update_user_plan, get_global_metrics
from providers.database.history import HistoryModule, list_scan_history
from fastapi.responses import PlainTextResponse
from scamLens.paths import LOG_DIR

from api.middleware.limiter import RateLimitedRoute

router = APIRouter(route_class=RateLimitedRoute, prefix="/api/admin", tags=["admin"])

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
    module: HistoryModule | None = None,
    user_id: int | None = Query(None, ge=1),
    admin: dict = Depends(get_current_admin),
):
    _audit(admin["id"], "read_scans", detail=f"module={module} user_id={user_id} limit={limit} offset={offset}")
    return list_scan_history(module=module, user_id=user_id, limit=limit, offset=offset)

@router.get("/request-logs")
def get_logs(
    limit: int = Query(default=200, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    module: Literal["scurl", "scqr", "scfs", "scpix", "chat"] | None = None,
    scan_id: str | None = Query(None, min_length=1, max_length=128),
    user_id: int | None = Query(None, ge=1),
    status_code: int | None = Query(None, ge=100, le=599),
    admin: dict = Depends(get_current_admin),
):
    _audit(admin["id"], "read_logs", detail=f"module={module} scan_id={scan_id} user_id={user_id} status_code={status_code} limit={limit} offset={offset}")
    conn = get_connection()
    filters = {"module": module, "scan_id": scan_id, "user_id": user_id, "status_code": status_code}
    conditions = [f"{name} = ?" for name, value in filters.items() if value is not None]
    values = [value for value in filters.values() if value is not None]
    where = " WHERE " + " AND ".join(conditions) if conditions else ""
    rows = conn.execute(
        f"SELECT * FROM request_logs{where} ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?",
        (*values, limit, offset),
    ).fetchall()
    return [dict(r) for r in rows]

def _safe_log_path(filename: str) -> Path:
    base = LOG_DIR.resolve()
    candidate = (base / filename).resolve()

    if (
        base not in candidate.parents
        or not (candidate.name == "host_info.txt"
                or re.search(r"\.log(?:\.[1-9][0-9]*)?$", candidate.name, re.IGNORECASE))
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
    for f in sorted(LOG_DIR.rglob("*")):
        if f.name != "host_info.txt" and not re.search(r"\.log(?:\.[1-9][0-9]*)?$", f.name, re.IGNORECASE):
            continue
        try:
            path = _safe_log_path(f.relative_to(LOG_DIR).as_posix())
            stat = path.stat()
        except (HTTPException, OSError):
            continue
        relative = f.relative_to(LOG_DIR)
        files.append({
            "name": relative.as_posix(),
            "session": relative.parts[0] if len(relative.parts) > 1 else None,
            "size_bytes": stat.st_size,
            "modified_at": stat.st_mtime,
        })
    return {"logs": files}

def _reverse_log_lines(path):
    with path.open("rb") as fh:
        position = fh.seek(0, 2)
        pending = b""
        while position:
            size = min(position, 65536)
            position -= size
            fh.seek(position)
            parts = (fh.read(size) + pending).split(b"\n")
            pending = parts[0]
            for line in reversed(parts[1:]):
                if line:
                    yield line.removesuffix(b"\r").decode("utf-8", errors="replace") + "\n"
        if pending:
            yield pending.removesuffix(b"\r").decode("utf-8", errors="replace") + "\n"

@router.get("/logs/{filename:path}")
def read_log(
    filename: str,
    tail: int = Query(500, ge=1, le=10000, description="últimas N linhas"),
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] | None = Query(None),
    category: Literal["server", "request", "scanner", "dependency"] | None = Query(None),
    admin=Depends(get_current_admin),
):
    path = _safe_log_path(filename)
    _audit(admin["id"], "read_log", detail=f"file={filename} tail={tail} level={level} category={category}")
    lines = []
    for line in _reverse_log_lines(path):
        if level is not None or category is not None:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            if level is not None and entry.get("level") != level:
                continue
            if category is not None and entry.get("category") != category:
                continue
        lines.append(line)
        if len(lines) == tail:
            break
    return PlainTextResponse("".join(reversed(lines)))
