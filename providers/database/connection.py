import sqlite3
from pathlib import Path
import threading
from scamLens import config

DB_PATH = Path(config["paths"]["scamlens_db_path"])
BASE_DIR = Path(__file__).parent.parent.parent
SCHEMA_FILE = BASE_DIR / "providers" / "database" / "schema" / "scans.sql"
SCHEMA_DIR = BASE_DIR / "providers" / "database" / "schema"
_local = threading.local()

def get_connection() -> sqlite3.Connection:
    if not hasattr(_local, "conn"):
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(DB_PATH, timeout=config["database"]["timeout"], check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return _local.conn

def close_connection() -> None:
    if hasattr(_local, "conn"):
        _local.conn.close()
        del _local.conn

def init_db() -> None:
    schemas = ["scans.sql", "plans.sql", "users.sql", "quota.sql", "usage.sql", "logging.sql", "revoked_tokens.sql", "admin_audit_log.sql", "chat.sql", "module_scans.sql"]
    conn = get_connection()

    for filename in schemas:
        schema = (SCHEMA_DIR / filename).read_text(encoding="utf-8")
        conn.executescript(schema)

    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "is_admin" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        conn.commit()

    cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
    if "user_id" not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")

    log_columns = {row[1] for row in conn.execute("PRAGMA table_info(request_logs)")}
    if "module" not in log_columns:
        conn.execute("ALTER TABLE request_logs ADD COLUMN module TEXT")
    conn.execute("""
        UPDATE request_logs SET module = CASE
            WHEN endpoint LIKE '/api/scurl/qr/%' OR endpoint LIKE '/api/qr/%' THEN 'scqr'
            WHEN endpoint LIKE '/api/scurl/%' THEN 'scurl'
            WHEN endpoint LIKE '/api/scfs/%' THEN 'scfs'
            WHEN endpoint LIKE '/api/scpix/%' THEN 'scpix'
            WHEN endpoint LIKE '/api/chat/%' THEN 'chat'
        END
        WHERE module IS NULL
          AND (endpoint LIKE '/api/scurl/%' OR endpoint LIKE '/api/qr/%'
               OR endpoint LIKE '/api/scfs/%' OR endpoint LIKE '/api/scpix/%'
               OR endpoint LIKE '/api/chat/%')
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_module_time ON request_logs(module, timestamp DESC, id DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_scan_id ON request_logs(scan_id)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_user_id ON request_logs(user_id)")
    conn.commit()
