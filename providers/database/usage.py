from providers.database.connection import get_connection
from scamLens import config

PLAN_LIMITS = config["quota"]["plans"]

def get_daily_count(user_id: int, module: str) -> int:
    row = get_connection().execute(
        """
        SELECT count FROM daily_usage
        WHERE user_id = ? AND module = ? AND date = DATE('now')
        """,
        (user_id, module)
    ).fetchone()
    return row["count"] if row else 0

def increment_usage(user_id: int, module: str) -> None:
    conn = get_connection()
    conn.execute(
        """
        INSERT INTO daily_usage (user_id, module, count)
        VALUES (?, ?, 1)
        ON CONFLICT(user_id, module, date) DO UPDATE SET
            count = count + 1
        """,
        (user_id, module)
    )
    conn.commit()

def is_usage_exceeded(user_id: int, module: str, plan_name: str, is_admin: bool = False) -> bool:
    if is_admin:
        return False
    limit = PLAN_LIMITS.get(plan_name)
    if limit is None or limit < 0:
        return False
    return get_daily_count(user_id, module) >= limit

def reserve_usage(user_id: int, module: str, plan_name: str, is_admin: bool = False) -> str | None:
    limit = -1 if is_admin else PLAN_LIMITS.get(plan_name, -1)
    if limit == 0:
        return None
    conn = get_connection()
    date = conn.execute("SELECT DATE('now')").fetchone()[0]
    with conn:
        cursor = conn.execute(
            """INSERT INTO daily_usage (user_id, module, date, count)
               VALUES (?, ?, ?, 1)
               ON CONFLICT(user_id, module, date) DO UPDATE SET count = count + 1
               WHERE ? < 0 OR count < ?""",
            (user_id, module, date, limit, limit),
        )
    return date if cursor.rowcount == 1 else None

def refund_usage(user_id: int, module: str, date: str) -> None:
    with get_connection() as conn:
        conn.execute(
            """UPDATE daily_usage SET count = count - 1
               WHERE user_id = ? AND module = ? AND date = ? AND count > 0""",
            (user_id, module, date),
        )
