from pathlib import Path
from typing import Optional
from ..models.scan_context import ScanContext
from .pipeline.metadata import _hashing_data
from .pipeline import (
    validate_input
)

def run_engine(source: Path | bytes, file_hint: Optional[str] = None) -> dict | ScanContext:
    ctx = ScanContext(source=source, file_hint=file_hint, image_data=source)
    
    if error := validate_input(ctx):
        return error
    
    if isinstance(source, Path):
        try:
            ctx.content_bytes = source.read_bytes()
        except OSError:
            return {"status": "error", "error": {"type": "invalid_path", "message": "Arquivo inacessível"}}
        ctx.image_name = source.name
    else:
        ctx.content_bytes = source
        ctx.image_name = file_hint or ""
    ctx.image_size = len(ctx.content_bytes)
    _hashing_data(ctx)
    return ctx
