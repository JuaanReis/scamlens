from providers.database.connection import get_connection

def create_user(email: str, name: str, hashed_password: str | None = None) -> dict:
    conn = get_connection()
    with conn:
        cursor = conn.execute(
            """
            INSERT INTO users (email, name, password)
            VALUES (?, ?, ?)
            """,
            (email, name, hashed_password)
        )
    return get_user_by_id(cursor.lastrowid)

def get_user_by_id(user_id: int) -> dict | None:
    row = get_connection().execute(
        """
        SELECT u.id, u.email, u.name, u.avatar_url, u.is_active, u.is_admin, u.created_at,
               p.name AS plan_name, p.label AS plan_label, p.price AS plan_price
        FROM users u
        JOIN plans p ON p.id = u.plan_id
        WHERE u.id = ?
        """,
        (user_id,)
    ).fetchone()
    return dict(row) if row else None

def get_user_by_email(email: str) -> dict | None:
    row = get_connection().execute(
        """
        SELECT u.id, u.email, u.name, u.avatar_url, u.password, u.is_active,
               p.name AS plan_name, p.label AS plan_label, p.price AS plan_price
        FROM users u
        JOIN plans p ON p.id = u.plan_id
        WHERE u.email = ?
        """,
        (email,)
    ).fetchone()
    return dict(row) if row else None

def update_user_plan(user_id: int, plan_name: str) -> None:
    conn = get_connection()
    conn.execute(
        """
        UPDATE users SET plan_id = (SELECT id FROM plans WHERE name = ?),
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE id = ?
        """,
        (plan_name, user_id)
    )
    conn.commit()

def update_avatar(user_id: int, avatar_url: str) -> None:
    conn = get_connection()
    conn.execute(
        """
        UPDATE users SET avatar_url = ?,
                         updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
        WHERE id = ?
        """,
        (avatar_url, user_id)
    )
    conn.commit()

def list_users(limit: int = 50, offset: int = 0) -> list[dict]:
    rows = get_connection().execute(
        """
        SELECT u.id, u.email, u.name, u.avatar_url, u.is_active, u.is_admin,
               u.created_at, p.name AS plan_name, p.label AS plan_label
        FROM users u
        JOIN plans p ON p.id = u.plan_id
        ORDER BY u.created_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset)
    ).fetchall()
    return [dict(row) for row in rows]

def set_user_active(user_id: int, is_active: bool) -> None:
    conn = get_connection()
    conn.execute(
        "UPDATE users SET is_active = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') WHERE id = ?",
        (int(is_active), user_id)
    )
    conn.commit()

def get_global_metrics() -> dict:
    from providers.database.history import scan_activity

    conn = get_connection()
    total_users = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    activity = scan_activity()
    return {
        "total_users": total_users,
        "total_scans": activity["total_scans"],
        "threats": activity["threats"],
        "anon_scans": activity["anonymous_scans"],
        "weekly": activity["weekly"],
    }
