from providers.database.connection import get_connection


def add_message(user_id: int, content: str, sent_at: str) -> int:
    conn = get_connection()
    with conn:
        row = conn.execute(
            "INSERT INTO chat_messages (user_id, content, sent_at) "
            "VALUES (?, ?, ?) RETURNING id",
            (user_id, content, sent_at),
        ).fetchone()
    return row["id"]


def get_recent_messages(limit: int = 50, before_id: int | None = None) -> list[dict]:
    conn = get_connection()
    params: list = []
    where = ""
    if before_id is not None:
        where = "WHERE m.id < ?"
        params.append(before_id)
    params.append(limit)

    rows = conn.execute(
        f"""
        SELECT m.id, m.content, m.sent_at, u.name, u.avatar_url
        FROM chat_messages m
        JOIN users u ON u.id = m.user_id
        {where}
        ORDER BY m.sent_at DESC, m.id DESC
        LIMIT ?
        """,
        params,
    ).fetchall()

    # Do mais antigo para o mais novo
    return [dict(r) for r in reversed(rows)]