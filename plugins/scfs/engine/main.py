from pathlib import Path
from typing import Optional
from ..models.scan_context import ScanContext
from .pipeline import (
    validate_input
)

def run_engine(source: Path | bytes, file_hint: Optional[str] = None) -> dict:
    ctx = ScanContext(source, file_hint)
    
    if error := validate_input(ctx):
        return error
    
    return ctx