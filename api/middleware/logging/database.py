import atexit
from datetime import datetime, timezone
import logging
from threading import RLock
from time import monotonic
from api.logs.batching import BatchWorker
from providers.database.connection import get_connection, close_connection
from scamLens import config

logger = logging.getLogger("api.logs.database")
_worker = None
_lock = RLock()

def start_request_logging():
    global _worker

    options = config["logs"]["database"]
    if not config["logs"]["enabled"] or not options["enabled"]:
        return

    with _lock:
        if _worker is not None:
            return

        last_cleanup = -options["cleanup_interval"]

        def consume(rows):
            nonlocal last_cleanup
            conn = None

            try:
                conn = get_connection()
                conn.executemany(
                    """INSERT INTO request_logs
                       (ip, endpoint, method, user_id, scan_id, status_code, duration_ms, module, timestamp)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""", rows,
                )

                if monotonic() - last_cleanup >= options["cleanup_interval"]:
                    conn.execute(
                        "DELETE FROM request_logs WHERE timestamp < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)",
                        (f"-{options['retention_days']} days",),
                    )
                    last_cleanup = monotonic()

                conn.execute(
                    """DELETE FROM request_logs WHERE id <= (
                        SELECT id FROM request_logs ORDER BY id DESC LIMIT 1 OFFSET ?
                    )""", (options["max_rows"],),
                )

                conn.commit()
            except Exception:
                if conn is not None:
                    conn.rollback()

                logger.exception("Could not persist request log batch (%d rows)", len(rows))

        def report_dropped(count):
            logger.warning("Request database queue full: discarded %d audit rows", count)

        class DatabaseWorker(BatchWorker):
            def _run(self):
                try:
                    super()._run()
                finally:
                    close_connection()

        _worker = DatabaseWorker(
            consume, batch_size=options["batch_size"], flush_interval=options["flush_interval"],
            queue_size=options["queue_size"], name="request-database-logs", report_dropped=report_dropped,
        )

def log_request(*, ip, endpoint, method, user_id, scan_id, status_code, duration_ms, module=None):
    worker = _worker
    if worker is None:
        return False
    created = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return worker.submit((ip, endpoint, method, user_id, scan_id, status_code, duration_ms, module, created))
def stop_request_logging():
    global _worker
    with _lock:
        if _worker is not None:
            worker, _worker = _worker, None
            worker.stop()

atexit.register(stop_request_logging)
