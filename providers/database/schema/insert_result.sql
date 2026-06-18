INSERT INTO scans (url_hash, url, score, risk_level, verdict, scan_id, timestamp, payload, user_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(url_hash) DO UPDATE SET
        payload   = excluded.payload,
        score     = excluded.score,
        risk_level = excluded.risk_level,
        verdict   = excluded.verdict,
        scan_id   = excluded.scan_id,
        timestamp = excluded.timestamp,
        user_id   = excluded.user_id