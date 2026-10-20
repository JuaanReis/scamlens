from time import sleep
from math import isfinite
from scamLens import config

def backoff_delay(attempt: int, base_delay: float = 0.6) -> None:
    sleep(base_delay * (2 ** attempt))

def should_retry(status_code: int) -> bool:
    return status_code in {429, 500, 502, 503, 504}

def get_retry_after(headers: dict, default: float = 1.0) -> float:
    headers = {key.lower(): value for key, value in headers.items()}
    try:
        delay = float(headers.get("retry-after", default))
    except (TypeError, ValueError):
        delay = default
    if not isfinite(delay):
        delay = default
    return max(0, min(delay, config["http"]["max_retry_delay"]))
