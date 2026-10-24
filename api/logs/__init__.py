import atexit
from copy import copy
from datetime import datetime, timezone
from hashlib import sha256
import json
import logging
from logging.handlers import RotatingFileHandler
import os
from platform import python_version, system, node
import re
import shutil
import sys
from threading import RLock
from time import time as timestamp
from uuid import uuid4
from scamLens import __version__, config, get_settings, logo
from scamLens.paths import LOG_DIR
from .batching import BatchWorker
from .locking import acquire_lock, release_lock, is_link
from .warning_aux import warning_aux_log

LOGS_ENABLED = config["logs"]["enabled"]
SESSION_ENV = "SCAMLENS_LOG_SESSION"
_SESSION_PATTERN = re.compile(r"sl_\d{8}T\d{12}Z_[0-9a-f]{8}\Z")
_LEASE_PATTERN = re.compile(r"(?:launcher|process)_\d+\.lock\Z")
_HOST_ID = sha256(node().casefold().encode()).hexdigest()
_runtime = None
_session_owner = None
_owner_lease = None
_lock = RLock()

def category(record):
    if record.name == "api.request" or record.name.startswith("uvicorn.access"):
        return "request"
    if record.name == "scanner" or record.name.startswith("scanner."):
        return "scanner"
    if record.name in ("root", "api", "providers", "plugins") or record.name.startswith(
        ("api.", "providers.", "plugins.", "uvicorn", "fastapi", "scamLens")
    ):
        return "server"
    return "dependency"

class CategoryFilter(logging.Filter):
    def filter(self, record):
        record.category = category(record)
        options = config["logs"]
        level = options.get(f"{record.category}_level", options["level"])
        for name in sorted(options["levels"], key=len, reverse=True):
            if record.name == name or record.name.startswith(name + "."):
                level = options["levels"][name]
                break
        return record.levelno >= logging._nameToLevel[level.upper()]

class JsonFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            "time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "category": getattr(record, "category", category(record)),
            "pid": record.process,
            "logger": record.name,
            "message": record.getMessage(),
        }
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = record.stack_info
        return json.dumps(payload, ensure_ascii=False)

class BatchFileHandler(RotatingFileHandler):

    def _open(self):
        return open(self.baseFilename, self.mode, encoding=self.encoding, errors=self.errors, newline="\n")

    def write_batch(self, records):
        self.acquire()
        try:
            pending = []
            size = self.stream.tell()
            for record in records:
                line = self.format(record) + "\n"
                line_size = len(line.encode("utf-8", errors="backslashreplace"))
                if size and size + line_size > self.maxBytes:
                    if pending:
                        self.stream.write("".join(pending))
                        pending.clear()
                    self.doRollover()
                    size = 0
                pending.append(line)
                size += line_size
            if pending:
                self.stream.write("".join(pending))
            self.stream.flush()
        finally:
            self.release()

class QueuedHandler(logging.Handler):
    def __init__(self, worker):
        super().__init__()
        self.worker = worker

    def emit(self, record):
        # Preserve traceback and defer formatting/I/O to the consumer.
        if not self.worker.submit(copy(record)) and record.levelno >= logging.ERROR:
            sys.stderr.write(JsonFormatter().format(record) + "\n")

def _registry(session, create=False):
    base = LOG_DIR.resolve()
    root = base / ".locks"
    path = root / session
    if not _SESSION_PATTERN.fullmatch(session) or is_link(root) or is_link(path):
        raise OSError("Invalid log session lock directory")
    if create:
        root.mkdir(exist_ok=True)
        path.mkdir(exist_ok=True)
    if path.resolve().parent != root or root.resolve().parent != base:
        raise OSError("Log session lock directory escapes storage")
    return path

def _known_session(path):
    marker = path / ".session.json"
    if is_link(path) or is_link(marker):
        return False
    try:
        data = json.loads(marker.read_text(encoding="utf-8"))
        return data == {"version": 1, "host": _HOST_ID, "session": path.name}
    except (OSError, ValueError):
        return False

def _last_activity(path):
    latest = path.stat().st_mtime
    for item in path.iterdir():
        if is_link(item):
            raise OSError("Linked log session entry")
        latest = max(latest, item.stat().st_mtime)
        if item.is_dir():
            if not re.fullmatch(r"process_\d+", item.name):
                raise OSError("Unknown log session directory")
            for entry in item.iterdir():
                log_pattern = re.escape(item.name) + r"\.log(?:\.\d+)?"
                if (is_link(entry) or not entry.is_file()
                        or (entry.name != "host_info.txt" and not re.fullmatch(log_pattern, entry.name))):
                    raise OSError("Unknown process log entry")
                latest = max(latest, entry.stat().st_mtime)
        elif item.name not in (".session.json", ".closed"):
            raise OSError("Unknown log session entry")
    return latest

def _prune_sessions():
    options = config["logs"]
    base = LOG_DIR.resolve()
    try:
        sessions = sorted((path for path in base.iterdir() if _SESSION_PATTERN.fullmatch(path.name)),
                          key=lambda path: path.name, reverse=True)
    except OSError as exc:
        sys.stderr.write(f"Could not list log sessions: {exc}\n")
        return
    now = timestamp()
    cutoff = now - options["retention_days"] * 86400
    completed = 0
    for path in sessions:
        gate = None
        leases = []
        removed = False
        registry = None
        try:
            if not path.is_dir() or not _known_session(path) or _last_activity(path) > now - 60:
                continue
            registry = _registry(path.name)
            gate = acquire_lock(registry / "gate.lock")
            if not _known_session(path):
                continue
            entries = list(registry.iterdir())
            if any(is_link(entry) or not entry.is_file()
                   or (entry.name != "gate.lock" and not _LEASE_PATTERN.fullmatch(entry.name)) for entry in entries):
                continue
            lease_paths = [entry for entry in entries if _LEASE_PATTERN.fullmatch(entry.name)]
            if not any(entry.name.startswith("launcher_") for entry in lease_paths):
                continue
            registered = {entry.name.removesuffix(".lock") for entry in lease_paths}
            if any(item.is_dir() and item.name not in registered for item in path.iterdir()):
                continue
            for entry in lease_paths:
                leases.append(acquire_lock(entry))
            latest = _last_activity(path)
            if latest > now - 60:
                continue
            expired = latest < cutoff or completed >= options["max_sessions"] - 1
            completed += 1
            if expired and path.resolve().parent == base and not is_link(path):
                shutil.rmtree(path)
                removed = True
        except OSError as exc:
            if not isinstance(exc, (PermissionError, BlockingIOError)):
                sys.stderr.write(f"Could not inspect log session {path.name}: {exc}\n")
        finally:
            for handle in reversed(leases):
                release_lock(handle)
            release_lock(gate)
        if removed:
            try:
                if (registry.resolve().parent == (base / ".locks").resolve()
                        and not is_link(registry) and not path.exists()):
                    shutil.rmtree(registry)
            except OSError:
                pass

def start_log_session():
    global _session_owner, _owner_lease
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    session = datetime.now(timezone.utc).strftime("sl_%Y%m%dT%H%M%S%fZ_") + uuid4().hex[:8]
    path = LOG_DIR / session
    path.mkdir()
    registry = _registry(session, create=True)
    gate = acquire_lock(registry / "gate.lock", timeout=1)
    try:
        (path / ".session.json").write_text(
            json.dumps({"version": 1, "host": _HOST_ID, "session": session}), encoding="utf-8",
        )
        lease = acquire_lock(registry / f"launcher_{os.getpid()}.lock")
    finally:
        release_lock(gate)
    if _owner_lease is not None and _owner_lease[0] == os.getpid():
        release_lock(_owner_lease[2])
    _owner_lease = (os.getpid(), session, lease)
    os.environ[SESSION_ENV] = session
    _session_owner = os.getpid()
    _prune_sessions()
    return path

def write_host_info(path, bootstrap_time=None):
    setting = get_settings()
    mode = setting.environment.upper()
    production = setting.environment == "production"
    host = node()
    details = {
        "Started": datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %z"),
        "PID": os.getpid(),
        "Session": path.parent.parent.name,
        "Python": python_version(),
        "Host": host if host and not production else "xxxx",
        "Platform": system() if not production else "xxxx",
        "Mode": mode if production else "dev",
        "Logging": config["logs"]["level"].upper() if not production else "xxxx",
        "Reload": config["server"]["reload"] if not production else "xxxx",
        "Bootstrap": f"{(bootstrap_time or 0):.2f}s",
    }
    content = f"{logo.rstrip()}   {__version__}\n\n"
    content += "".join(f":: {label:<10} {value}\n" for label, value in details.items())
    path.write_text(content, encoding="utf-8")

def initialize_logging(time=None):
    global _runtime
    if not LOGS_ENABLED:
        return None
    with _lock:
        pid = os.getpid()
        if _runtime is not None and _runtime["pid"] == pid:
            return _runtime["path"]
        session = os.environ.get(SESSION_ENV, "")
        if not _SESSION_PATTERN.fullmatch(session) or not _known_session(LOG_DIR / session):
            start_log_session()
            session = os.environ[SESSION_ENV]
        session_dir = LOG_DIR / session
        lease = None
        for attempt in range(2):
            registry = _registry(session)
            gate = None
            try:
                gate = acquire_lock(registry / "gate.lock", timeout=1)
                if _known_session(session_dir):
                    lease = acquire_lock(registry / f"process_{pid}.lock")
                    process_dir = session_dir / f"process_{pid}"
                    process_dir.mkdir(exist_ok=True)
                    break
            except FileNotFoundError:
                if lease is not None:
                    release_lock(lease)
                    lease = None
            except BaseException:
                release_lock(lease)
                raise
            finally:
                release_lock(gate)
            if attempt == 0:
                session_dir = start_log_session()
                session = session_dir.name
        if lease is None:
            raise OSError("Log session ended before process registration")
        path = process_dir / f"process_{pid}.log"
        options = config["logs"]
        sink = None
        try:
            write_host_info(process_dir / "host_info.txt", time)
            sink = BatchFileHandler(
                path, maxBytes=options["max_bytes"], backupCount=options["backup_count"],
                encoding="utf-8", errors="backslashreplace",
            )
            sink.setFormatter(JsonFormatter())
        except BaseException:
            if sink is not None:
                sink.close()
            release_lock(lease)
            raise

        def report_dropped(count):
            record = logging.LogRecord("api.logs", logging.WARNING, __file__, 0,
                                       "Log queue full: discarded %d records", (count,), None)
            sink.write_batch([record])

        worker = BatchWorker(
            sink.write_batch, batch_size=options["batch_size"],
            flush_interval=options["flush_interval"], queue_size=options["queue_size"],
            name=f"file-logs-{pid}", report_dropped=report_dropped,
        )

        handler = QueuedHandler(worker)
        handler.addFilter(CategoryFilter())
        root = logging.getLogger()
        root_level = root.level
        levels = [options["level"], *(options[name] for name in
                  ("request_level", "scanner_level", "dependency_level")), *options["levels"].values()]
        minimum = min(logging._nameToLevel[level.upper()] for level in levels)
        root.setLevel(minimum)
        root.addHandler(handler)
        snapshots = []

        for name in ("uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi", "fastapi", "api", "api.request", "scanner", "scanner.request", "scanner.rdap", "scanner.dns", "scanner.ssl", *options["levels"]):

            logger = logging.getLogger(name)
            if any(item[0] is logger for item in snapshots):
                continue

            snapshots.append((logger, logger.handlers[:], logger.level, logger.propagate))
            logger.handlers = []
            logger.setLevel(minimum)
            logger.propagate = name != "uvicorn.access"

        console = None
        if options["console"]:
            console = logging.StreamHandler()
            console.setLevel(options["console_level"].upper())
            console.addFilter(CategoryFilter())
            console.setFormatter(logging.Formatter("%(levelname)s [%(category)s] %(name)s: %(message)s"))
            root.addHandler(console)

        _runtime = dict(pid=pid, path=path, session_dir=session_dir, sink=sink, worker=worker,
                        handler=handler, console=console, snapshots=snapshots, root_level=root_level, lease=lease)

        logging.getLogger("api.server").info(
            "ScamLens %s process started; bootstrap=%.3fs; session=%s",
            __version__, time or 0, session,
        )

        for warning in warning_aux_log().splitlines():
            if warning:
                logging.getLogger("api.server").warning("%s", warning)

        return path

def flush_logging():
    if _runtime is not None and _runtime["pid"] == os.getpid():
        _runtime["worker"].flush()

def shutdown_logging():
    global _runtime, _owner_lease
    with _lock:
        if _runtime is None or _runtime["pid"] != os.getpid():
            return
        runtime, _runtime = _runtime, None
        root = logging.getLogger()
        root.removeHandler(runtime["handler"])
        if runtime["console"] is not None:
            root.removeHandler(runtime["console"])
            runtime["console"].close()
        runtime["worker"].stop()
        runtime["handler"].close()
        runtime["sink"].close()
        for logger, handlers, level, propagate in runtime["snapshots"]:
            logger.handlers, logger.level, logger.propagate = handlers, level, propagate
        root.setLevel(runtime["root_level"])
        release_lock(runtime["lease"])
        if _session_owner == os.getpid():
            (runtime["session_dir"] / ".closed").touch()
            if _owner_lease is not None and _owner_lease[:2] == (os.getpid(), runtime["session_dir"].name):
                release_lock(_owner_lease[2])
                _owner_lease = None

atexit.register(shutdown_logging)
