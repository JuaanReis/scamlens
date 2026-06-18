CREATE TABLE IF NOT EXISTS daily_usage (
    user_id    INTEGER NOT NULL REFERENCES users(id),
    module     TEXT    NOT NULL,
    date       TEXT    NOT NULL DEFAULT (DATE('now')),
    count      INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, module, date)
);