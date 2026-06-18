CREATE TABLE IF NOT EXISTS plans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL UNIQUE,  -- standard | go_pro | plus_premium
    label       TEXT    NOT NULL,
    price       INTEGER NOT NULL,         -- em centavos (0, 4900, 19900)
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

INSERT OR IGNORE INTO plans (name, label, price) VALUES
    ('standard',     'Standard (Gratuito)', 0),
    ('go_pro',       'Go Pro',              4900),
    ('plus_premium', 'Plus Premium',        19900);