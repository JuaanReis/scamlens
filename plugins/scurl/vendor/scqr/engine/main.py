from pathlib import Path
from plugins.scurl.vendor.scqr.models.scan_context import ScanContext
from plugins.scurl.vendor.scqr.engine.pipeline import response_build, classify_qrcode, decode_qrcode, detect_extension, is_qrcode, resolve_bytes

def run_engine(src: bytes | str | Path):
    ctx = ScanContext(src)

    if error := resolve_bytes(ctx):
        return error

    if error := detect_extension(ctx):
        return error

    if error := decode_qrcode(ctx):
        return error
    
    if error := is_qrcode(ctx):
        return error
    
    classify_qrcode(ctx)

    return response_build(ctx)