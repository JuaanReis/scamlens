CREATE TABLE IF NOT EXISTS anonymous_quota (
    ip          TEXT    NOT NULL PRIMARY KEY,
    scan_count  INTEGER NOT NULL DEFAULT 0,
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);