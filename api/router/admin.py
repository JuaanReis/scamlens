from fastapi import APIRouter, Depends, Query
from api.middleware.auth import get_current_admin
from providers.database.connection import get_connection
from providers.database.users import list_users, set_user_active, update_user_plan, get_global_metrics
from providers.database.repository import list_scans

router = APIRouter(prefix="/api/admin", tags=["admin"])

@router.get("/metrics")
def metrics(admin: dict = Depends(get_current_admin)):
    return get_global_metrics()

@router.get("/users")
def get_users(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: dict = Depends(get_current_admin)
):
    return {"users": list_users(limit=limit, offset=offset)}

@router.patch("/users/{user_id}/active")
def toggle_active(user_id: int, is_active: bool, admin: dict = Depends(get_current_admin)):
    set_user_active(user_id, is_active)
    return {"ok": True}

@router.patch("/users/{user_id}/plan")
def change_plan(user_id: int, plan_name: str, admin: dict = Depends(get_current_admin)):
    valid = {"standard", "go_pro", "plus_premium"}
    if plan_name not in valid:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail=f"Plano inválido. Use: {valid}")
    update_user_plan(user_id, plan_name)
    return {"ok": True}

@router.get("/scans")
def get_all_scans(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    admin: dict = Depends(get_current_admin)
):
    return {"scans": list_scans(limit=limit, offset=offset)}

@router.get("/logs")
def get_logs(current_admin: dict = Depends(get_current_admin)):
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM request_logs ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    return [dict(r) for r in rows]