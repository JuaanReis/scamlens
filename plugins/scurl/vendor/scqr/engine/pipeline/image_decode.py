import io
from PIL import Image
from plugins.scurl.vendor.scqr.models.scan_context import ScanContext
from collections import namedtuple
from zxingcpp import read_barcodes

Point = namedtuple("Point", ["x", "y"])

def _decode(image):
        results = read_barcodes(image)
        out = []
        for r in results:
            pos = r.position
            points = [
                Point(pos.top_left.x, pos.top_left.y),
                Point(pos.top_right.x, pos.top_right.y),
                Point(pos.bottom_right.x, pos.bottom_right.y),
                Point(pos.bottom_left.x, pos.bottom_left.y),
            ]
            out.append((r.text, points))
        return out

def decode_qrcode(ctx: ScanContext) -> dict | None:
    try:
        image = Image.open(io.BytesIO(ctx.src_resolved)).convert("L")
    except Exception:
        return {
            "status": "error",
            "meta": {
                "scan_time_s": 0
            },
            "error": {
                "type": "invalid_image",
                "message": "Não foi possível abrir a imagem"
            }
        }

    results = _decode(image)

    if not results:
        return None

    text, polygon = results[0]
    ctx.decoded = text
    ctx.points = polygon

    return None