from pathlib import Path
from scamLens import config

paths = config["paths"]
_STORAGE = Path(paths["storage"])
STATIC = Path(paths["static"])
LOG_DIR = Path(paths["logs"])

Path(paths["avatar"]).mkdir(parents=True, exist_ok=True)
_STORAGE.mkdir(parents=True, exist_ok=True)
