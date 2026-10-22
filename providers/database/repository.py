import json
from providers.database.connection import get_connection
from pathlib import Path

INSERT_FILE = Path(__file__).parent / "schema" / "insert_result.sql"

def list_scans(limit: int = 50, offset: int = 0) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT url, score, risk_level, verdict, scan_id, timestamp, url_hash "
        "FROM scans ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset)
    ).fetchall()
    return [dict(row) for row in rows]

def get_scan(identifier: str) -> tuple[dict, dict] | None:
    row = get_connection().execute(
        "SELECT payload FROM scans WHERE scan_id = ? OR url_hash = ?",
        (identifier, identifier)
    ).fetchone()

    if not row:
        return None

    data = json.loads(row["payload"])
    if "scan" in data:
        return data["scan"], data["target"]
    return data, {}

def list_scans_by_user(user_id: int, limit: int = 50, offset: int = 0) -> list[dict]:
    conn = get_connection()
    rows = conn.execute(
        "SELECT url, score, risk_level, verdict, scan_id, timestamp, url_hash "
        "FROM scans WHERE user_id = ? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (user_id, limit, offset)
    ).fetchall()
    return [dict(row) for row in rows]

def get_user_activity(user_id: int) -> dict:
    from providers.database.history import scan_activity

    conn = get_connection()
    activity = scan_activity(user_id)
    average = conn.execute(
        "SELECT AVG(duration_ms) FROM request_logs WHERE user_id = ? AND method = 'POST' AND scan_id IS NOT NULL AND status_code = 200",
        (user_id,),
    ).fetchone()[0]
    return {
        "total_scans": activity["total_scans"],
        "avg_response_ms": round(average, 2) if average is not None else 0,
        "threats_detected": activity["threats"],
        "weekly": activity["weekly"],
    }

_INSERT_QUERY = INSERT_FILE.read_text(encoding="utf-8")

def save_scan(scan: dict, target: dict, user_id: int | None = None) -> None:
    url_hash = scan["meta"]["url_hash"]
    payload = json.dumps({"scan": scan, "target": target})
    conn = get_connection()
    conn.execute(_INSERT_QUERY, (
        url_hash,
        scan["meta"].get("url", ""),
        scan["result"]["score"],
        scan["result"]["risk_level"],
        scan["result"]["verdict"],
        scan["meta"]["scan_id"],
        scan["meta"]["timestamp"],
        payload,
        user_id
    ))
    conn.commit()

def count_scans() -> int:
    return get_connection().execute("SELECT COUNT(*) FROM scans").fetchone()[0]

def find_by_hash(url_hash: str) -> tuple[dict, dict] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT payload FROM scans WHERE url_hash = ?", (url_hash,)
        ).fetchone()

    if not row:
        return None

    data = json.loads(row["payload"])

    if "scan" in data:
        return data["scan"], data["target"]
    return data, {}
