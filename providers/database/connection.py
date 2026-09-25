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
        conn = sqlite3.connect(DB_PATH, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        _local.conn = conn
    return _local.conn

def init_db() -> None:
    schemas = ["scans.sql", "plans.sql", "users.sql", "quota.sql", "usage.sql", "logging.sql", "revoked_tokens.sql", "admin_audit_log.sql"]
    conn = get_connection()

    for filename in schemas:
        schema = (SCHEMA_DIR / filename).read_text()
        conn.executescript(schema)

    cols = [r[1] for r in conn.execute("PRAGMA table_info(users)").fetchall()]
    if "is_admin" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        conn.commit()

    cols = [r[1] for r in conn.execute("PRAGMA table_info(scans)").fetchall()]
    if "user_id" not in cols:
        conn.execute("ALTER TABLE scans ADD COLUMN user_id INTEGER")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_user_id ON scans(user_id)")
        conn.commit()