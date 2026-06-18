CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url_hash    TEXT NOT NULL UNIQUE,
    url         TEXT NOT NULL,
    score       REAL,
    risk_level  TEXT,
    verdict     TEXT,
    scan_id     TEXT,
    timestamp   TEXT,
    payload     TEXT NOT NULL
);