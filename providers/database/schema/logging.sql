CREATE TABLE IF NOT EXISTS request_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    endpoint    TEXT NOT NULL,
    method      TEXT NOT NULL DEFAULT 'POST',
    user_id     INTEGER,
    scan_id     TEXT,
    status_code INTEGER,
    duration_ms REAL,
    timestamp   TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);