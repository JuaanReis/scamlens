__version__ = "1.1.0"

from scamLens import config
config = config.get("scurl", {})
from plugins.scurl.engine.main import run_engine