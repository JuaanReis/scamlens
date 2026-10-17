"""scfs: static executable heuristic scanner, standalone or embedded."""
__version__ = "1.1.0"
from .config import Settings
from .engine.main import run_engine
__all__ = ["run_engine", "Settings", "__version__"]
