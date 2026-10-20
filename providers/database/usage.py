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
