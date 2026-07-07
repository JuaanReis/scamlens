from scamLens import get_settings
import sqlite3
from datetime import datetime, timezone

settings = get_settings()

def ensure_admin_exists(conn: sqlite3.Connection) -> None:
    cur = conn.execute("SELECT 1 FROM users WHERE is_admin = 1 LIMIT 1")
    if cur.fetchone():
        return

    email = settings.email_admin
    password = settings.password_admin
    if not email or not password:
        raise RuntimeError(
            "ADMIN_SEED_EMAIL e ADMIN_SEED_PASSWORD precisam estar definidas no ambiente."
        )

    from api.router.auth import hash_password  
    hashed = hash_password(password)

    conn.execute(
        """
        INSERT INTO users (email, name, password, is_admin, is_active, created_at)
        VALUES (?, ?, ?, 1, 1, ?)
        """,
        (email, "Admin", hashed, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()