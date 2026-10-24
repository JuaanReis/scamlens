from providers.database.connection import get_connection
from scamLens import config

ANONYMOUS_LIMIT = config["quota"]["anonymous_daily_limit"]

def get_anonymous_count(ip: str) -> int:
    row = get_connection().execute(
        "SELECT scan_count FROM anonymous_quota WHERE ip = ? AND DATE(updated_at) = DATE('now')", (ip,)
    ).fetchone()
    return row["scan_count"] if row else 0

def increment_anonymous_count(ip: str) -> int:
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO anonymous_quota (ip, scan_count)
        VALUES (?, 1)
        ON CONFLICT(ip) DO UPDATE SET
            scan_count = CASE WHEN DATE(updated_at) = DATE('now') THEN scan_count + 1 ELSE 1 END,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        """,
        (ip,)
    )
    conn.commit()
    return get_anonymous_count(ip)

def is_quota_exceeded(ip: str) -> bool:
    if ANONYMOUS_LIMIT < 0:
        return False
    return get_anonymous_count(ip) >= ANONYMOUS_LIMIT

def reserve_anonymous_count(ip: str) -> str | None:
    if ANONYMOUS_LIMIT == 0:
        return None
    conn = get_connection()
    date = conn.execute("SELECT DATE('now')").fetchone()[0]
    with conn:
        cursor = conn.execute(
            """INSERT INTO anonymous_quota (ip, scan_count, updated_at)
               VALUES (?, 1, ? || strftime('T%H:%M:%fZ', 'now'))
               ON CONFLICT(ip) DO UPDATE SET
                   scan_count = CASE WHEN DATE(updated_at) = ? THEN scan_count + 1 ELSE 1 END,
                   updated_at = excluded.updated_at
               WHERE DATE(updated_at) != ? OR ? < 0 OR scan_count < ?""",
            (ip, date, date, date, ANONYMOUS_LIMIT, ANONYMOUS_LIMIT),
        )
    return date if cursor.rowcount == 1 else None

def refund_anonymous_count(ip: str, date: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """UPDATE anonymous_quota SET scan_count = scan_count - 1
               WHERE ip = ? AND DATE(updated_at) = ? AND scan_count > 0""",
            (ip, date),
        )
