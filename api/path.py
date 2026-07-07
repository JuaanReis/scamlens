from pathlib import Path

_BASE = Path(__file__).parent
_STATIC = _BASE / "static"
_STORAGE = _BASE.parent / "providers" / "database" / "storage"
_LOG_DIR = _STORAGE / "logs"

(_STORAGE / "avatars").mkdir(parents=True, exist_ok=True)