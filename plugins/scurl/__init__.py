__version__ = "1.1.0"

from pathlib import Path
import tomllib

_CONFIG_PATH = Path(__file__).parent / "config.toml"

with _CONFIG_PATH.open("rb") as f:
    config = tomllib.load(f)

from plugins.scurl.engine.main import run_engine