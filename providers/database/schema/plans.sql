CREATE TABLE IF NOT EXISTS plans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE, 
    label       TEXT    NOT NULL,
    price       INTEGER NOT NULL,        
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO plans (name, label, price) VALUES
    ('standard',     'Standard (Gratuito)', 0),
    ('go_pro',       'Go Pro',              4900),
    ('plus_premium', 'Plus Premium',        19900);