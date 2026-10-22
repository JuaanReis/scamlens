"""Stored analysis results; input files and raw Pix payloads are never stored."""
import json
from typing import Literal

from providers.database.connection import get_connection

HistoryModule = Literal["scurl", "scfs", "scpix"]
StoredModule = Literal["scfs", "scpix"]

# URL/QR retain the existing cache table and its one-row-per-URL semantics.
HISTORY_SQL = """
    SELECT 'scurl' AS module, scan_id, url_hash AS target_hash, url AS target_name,
           'ok' AS status, score, risk_level, verdict, NULL AS scan_time_s,
           timestamp, user_id, url, url_hash
    FROM scans
    UNION ALL
    SELECT module, scan_id, target_hash, target_name, status, score, risk_level,
           verdict, scan_time_s, timestamp, user_id, NULL AS url, NULL AS url_hash
    FROM module_scans
"""


def save_module_scan(module: StoredModule, scan: dict, target: dict, user_id: int | None = None) -> None:
    if module not in ("scfs", "scpix") or scan["engine"]["name"] != module:
        raise ValueError("Módulo de histórico inválido")
    if scan["status"] not in ("ok", "partial", "inconclusive"):
        raise ValueError("Somente análises concluídas podem entrar no histórico")
    meta, result = scan["meta"], scan["result"]
    identity = target["identity"]
    target_name = identity["name"] if module == "scfs" else target["pix"].get("merchant_name") or "Pix"
    payload = json.dumps({"scan": scan, "target": target}, ensure_ascii=False)
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO module_scans (
                module, scan_id, target_hash, target_name, status, score,
                risk_level, verdict, scan_time_s, timestamp, user_id, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            module, meta["scan_id"], identity["sha256"], target_name, scan["status"],
            result["score"], result["risk_level"], result["verdict"],
            meta["scan_time_s"], meta["timestamp"], user_id, payload,
        ))


def _filters(module=None, user_id=None, target_hash=None):
    conditions, values = [], []
    if module is not None:
        if module not in ("scurl", "scfs", "scpix"):
            raise ValueError("Módulo de histórico inválido")
        conditions.append("module = ?")
        values.append(module)
    if user_id is not None:
        conditions.append("user_id = ?")
        values.append(user_id)
    if target_hash is not None:
        conditions.append("target_hash = ?")
        values.append(target_hash)
    return (" WHERE " + " AND ".join(conditions) if conditions else ""), values


def list_scan_history(*, module: HistoryModule | None = None, user_id: int | None = None,
                      target_hash: str | None = None, limit: int = 50, offset: int = 0) -> dict:
    where, values = _filters(module, user_id, target_hash)
    conn = get_connection()
    total = conn.execute(f"SELECT COUNT(*) FROM ({HISTORY_SQL}){where}", values).fetchone()[0]
    rows = conn.execute(
        f"SELECT * FROM ({HISTORY_SQL}){where} ORDER BY timestamp DESC, scan_id DESC LIMIT ? OFFSET ?",
        (*values, limit, offset),
    ).fetchall()
    return {"status": "ok", "total": total, "limit": limit, "offset": offset,
            "scans": [dict(row) for row in rows]}


def get_module_scan(module: StoredModule, scan_id: str, *, user_id: int | None = None) -> dict | None:
    where, values = _filters(module, user_id)
    row = get_connection().execute(
        f"SELECT payload FROM module_scans{where} AND scan_id = ?", (*values, scan_id)
    ).fetchone()
    return json.loads(row["payload"]) if row else None


def scan_activity(user_id: int | None = None) -> dict:
    where, values = _filters(user_id=user_id)
    conn = get_connection()
    totals = conn.execute(f"""
        SELECT COUNT(*) AS total_scans,
               COALESCE(SUM(risk_level IN ('high', 'very high', 'critical')), 0) AS threats,
               COALESCE(SUM(user_id IS NULL), 0) AS anonymous_scans
        FROM ({HISTORY_SQL}){where}
    """, values).fetchone()
    weekly = [conn.execute(
        f"SELECT COUNT(*) FROM ({HISTORY_SQL}){where}"
        + (" AND " if where else " WHERE ") + "DATE(timestamp) = DATE('now', ? || ' days')",
        (*values, f"-{day}"),
    ).fetchone()[0] for day in range(5, -1, -1)]
    return {**dict(totals), "weekly": weekly}
