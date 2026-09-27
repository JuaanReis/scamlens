from providers.database.connection import get_connection

def log_request(
    *,
    ip: str,
    endpoint: str,
    method: str,
    user_id,
    scan_id,
    status_code: int,
    duration_ms: float
):
    conn = get_connection()

    conn.execute(
        """
        INSERT INTO request_logs (
            ip,
            endpoint,
            method,
            user_id,
            scan_id,
            status_code,
            duration_ms
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ip,
            endpoint,
            method,
            user_id,
            scan_id,
            status_code,
            duration_ms,
        ),
    )

    conn.commit()