from providers.database.repository import find_by_hash, save_scan

def load_cache(url_hash: str) -> tuple[dict, dict] | None:
    return find_by_hash(url_hash)

def persist_scan(scan_result: dict, target_data: dict) -> None:
    save_scan(scan_result, target_data)