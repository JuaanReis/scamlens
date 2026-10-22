"""SCPIX - análise offline de payloads Pix/BR Code."""
__version__ = "1.0.0"
from .config import Settings
from .engine.main import run_engine

__all__ = ["run_engine", "Settings", "__version__"]
