CREATE TABLE IF NOT EXISTS module_scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    module       TEXT NOT NULL CHECK (module IN ('scfs', 'scpix')),
    scan_id      TEXT NOT NULL UNIQUE,
    target_hash  TEXT NOT NULL,
    target_name  TEXT NOT NULL,
    status       TEXT NOT NULL,
    score        REAL,
    risk_level   TEXT NOT NULL,
    verdict      TEXT NOT NULL,
    scan_time_s  REAL NOT NULL,
    timestamp    TEXT NOT NULL,
    user_id      INTEGER REFERENCES users(id) ON DELETE SET NULL,
    payload      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_module_scans_module_time
    ON module_scans(module, timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_module_scans_user_module_time
    ON module_scans(user_id, module, timestamp DESC, id DESC);
CREATE INDEX IF NOT EXISTS idx_module_scans_target_hash
    ON module_scans(module, target_hash);
