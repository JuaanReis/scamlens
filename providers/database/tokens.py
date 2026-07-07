from datetime import datetime, timezone
from providers.database.connection import get_connection

def revoke_token(jti: str, expires_at: datetime) -> None:
    conn = get_connection()
    conn.execute(
        """
        INSERT OR IGNORE INTO revoked_tokens (jti, expires_at)
        VALUES (?, ?)
        """,
        (jti, expires_at.isoformat()),
    )
    conn.commit()

def is_token_revoked(jti: str) -> bool:
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    row = conn.execute(
        """
        SELECT 1 FROM revoked_tokens
        WHERE jti = ? AND expires_at > ?
        """,
        (jti, now),
    ).fetchone()
    return row is not None

def purge_expired_tokens() -> int:
    conn = get_connection()
    now = datetime.now(timezone.utc).isoformat()
    cursor = conn.execute(
        "DELETE FROM revoked_tokens WHERE expires_at <= ?",
        (now,),
    )
    conn.commit()
    return cursor.rowcount