from pathlib import Path
from scamLens import config

paths = config.get("paths", {})
_STORAGE = Path(paths.get("storage", ""))
_STATIC = Path(paths.get("static", ""))
_LOG_DIR = Path(paths.get("logs", ""))

(_STORAGE / "avatars").mkdir(parents=True, exist_ok=True)