from time import sleep

def backoff_delay(attempt: int, base_delay: float = 0.6) -> None:
    sleep(base_delay * (2 ** attempt))

def should_retry(status_code: int) -> bool:
    return status_code in {429, 500, 502, 503, 504}

def get_retry_after(headers: dict, default: float = 1.0) -> float:
    return float(headers.get("Retry-After", default))