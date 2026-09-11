from datetime import datetime
from os import getpid
from pathlib import Path
from time import perf_counter
import logging
from scamLens import __version__, config
from ..path import LOG_DIR
from scamLens import get_settings
from platform import python_version, system, node

setting = get_settings()

START = perf_counter()

LOGS_ENABLED = config.get("logs", {}).get("enabled", False)
LEVEL = config.get("logs", {}).get("level", "INFO").upper()
numeric_level = getattr(logging, LEVEL, logging.INFO)

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

def setup_logging(log_file: Path):
    global _initialized

    if _initialized:
        return

    with open(
        "./scamLens/logo_log.txt",
        "r",
        encoding="utf-8",
    ) as f:
        logo = f.read()

    with log_file.open("w", encoding="utf-8") as file:
        file.write(
            f"{logo}\n\n"
            f":: Started {datetime.now():%Y-%m-%d %H:%M:%S}\n"
            f":: Version ({__version__})\n"
            f":: Python Version ({python_version()})\n"
            f":: Platform ({system()})\n"
            f":: Host ({node() if node() else "-"})\n"
            f":: Mode ({setting.environment if setting.environment == "production" else "development"})\n\n"
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

def initialize_logging():
    if not LOGS_ENABLED:
        return None

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    log_file = LOG_DIR / (
        f"sl_{datetime.now():%Y-%m-%d_%H-%M-%S}"
        f"_pid{getpid()}.log"
    )

    setup_logging(log_file)

    return log_file