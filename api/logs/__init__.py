from datetime import datetime
from os import getpid
from pathlib import Path
import logging
from scamLens.paths import LOG_DIR
from scamLens import get_settings, logo, config, __version__
from platform import python_version, system, node
from .warning_aux import is_production as _is_production, warning_aux_log

setting = get_settings()
logs_config = config["logs"]
LOGS_ENABLED = logs_config["enabled"]
LEVEL = logs_config["level"].upper()
numeric_level = getattr(logging, LEVEL, logging.INFO)
HOST = node()

_initialized = False

class UTCFormatter(logging.Formatter):

    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(
            record.created
        ).astimezone()

        return (
            dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            + dt.strftime(" %z")
        )

def setup_logging(log_file: Path, bootstrap_time: float = None) -> None:
    global _initialized

    if _initialized:
        return
    
    LABEL_WIDTH = 10

    with log_file.open("w", encoding="utf-8") as f:
        f.write(
            f"{logo + "   " + __version__}\n\n"
            f":: {"Started":<{LABEL_WIDTH}} {datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f":: {"Python":<{LABEL_WIDTH}} {python_version()}\n"
            f":: {"Host":<{LABEL_WIDTH}} {HOST if HOST and not _is_production() else 'xxxx'}\n"
            f":: {"Platform":<{LABEL_WIDTH}} {system() if not _is_production() else 'xxxx'}\n"
            f":: {"Mode":<{LABEL_WIDTH}} {setting.environment.upper() if setting.environment == 'production' else 'development'.upper()}\n"
            f":: {"Logging":<{LABEL_WIDTH}} {LEVEL if not _is_production() else 'xxxx'}\n"
            f":: {"Reload":<{LABEL_WIDTH}} {config['server']['reload'] if not _is_production() else 'xxxx'}\n"
            f":: {"Bootstrap":<{LABEL_WIDTH}} {(bootstrap_time/1000):.2f}s\n"
            f"{warning_aux_log()}"
            f"\n"
        )

    handler = logging.FileHandler(
        log_file,
        encoding="utf-8",
    )

    handler.setFormatter(
        UTCFormatter(
            "%(asctime)s  %(levelname)s %(process)d --- [%(name)s] %(module)s.%(funcName)s: %(message)s"
        )
    )

    for name in (
        "uvicorn",
        "uvicorn.error",
        "fastapi",
        "api.request",
        "scanner.request",
        "scanner.rdap",
        "scanner.dns",
        "scanner.ssl"
    ):
        logger = logging.getLogger(name)

        logger.handlers.clear()
        logger.addHandler(handler)
        logger.setLevel(numeric_level)
        logger.propagate = False

    _initialized = True

def initialize_logging(time: float = None) -> Path | None:
    if not LOGS_ENABLED:
        return None

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    log_file = LOG_DIR / (
        f"sl_{datetime.now():%Y-%m-%d_%H-%M-%S}"
        f"_pid{getpid()}.log"
    )

    setup_logging(log_file, time)

    return log_file