from providers.database.connection import get_connection

ANONYMOUS_LIMIT = 3

def get_anonymous_count(ip: str) -> int:
    row = get_connection().execute(
        "SELECT scan_count FROM anonymous_quota WHERE ip = ?", (ip,)
    ).fetchone()
    return row["scan_count"] if row else 0

def increment_anonymous_count(ip: str) -> int:
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO anonymous_quota (ip, scan_count)
        VALUES (?, 1)
        ON CONFLICT(ip) DO UPDATE SET
            scan_count = scan_count + 1,
            updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        """,
        (ip,)
    )
    conn.commit()
    return get_anonymous_count(ip)

def is_quota_exceeded(ip: str) -> bool:
    return get_anonymous_count(ip) >= ANONYMOUS_LIMIT