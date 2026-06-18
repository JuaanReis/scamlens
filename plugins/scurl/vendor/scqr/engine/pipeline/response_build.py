from plugins.scurl.vendor.scqr.models.scan_context import ScanContext
from time import time

def response_build(ctx: ScanContext) -> dict | None:
    return {
        "status": "ok",
        "meta": {
            "scan_time_s": round(time() - ctx.start, 2)
        },
        "data": {
            "decoded": ctx.decoded,
            "points": [p._asdict() for p in ctx.points] if ctx.points else []
        },
        "result": {
            "qr_code_type": ctx.qr_type
        }
    }