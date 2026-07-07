CREATE TABLE IF NOT EXISTS admin_audit_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id       INTEGER NOT NULL,
    action         TEXT    NOT NULL,      
    target_user_id INTEGER,               
    detail         TEXT,                   
    timestamp      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_audit_admin_id
    ON admin_audit_log (admin_id);

CREATE INDEX IF NOT EXISTS idx_audit_target_user_id
    ON admin_audit_log (target_user_id);