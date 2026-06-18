import json
from plugins.scurl.vendor.scqr.models.scan_context import ScanContext

def classify_qrcode(ctx: ScanContext) -> None:
    ctx.qr_type = _detect_type(ctx.decoded)

def _detect_type(decoded: str) -> str:
    if not decoded:
        return "unknown"

    low = decoded.lower()

    if low.startswith(("http://", "https://")):
        return "url"

    if low.startswith("mailto:"):
        return "email"

    if low.startswith("tel:"):
        return "phone"

    if low.startswith("wifi:"):
        return "wifi"

    if low.startswith("begin:vcard"):
        return "contact"

    if low.startswith("begin:vevent"):
        return "calendar"

    if low.startswith("geo:"):
        return "location"

    if low.startswith("smsto:") or low.startswith("sms:"):
        return "sms"

    if _is_pix(decoded):
        return "pix"

    if _is_json(decoded):
        return "json"

    return "text"

def _is_pix(decoded: str) -> bool:
    return decoded.startswith("000201")

def _is_json(decoded: str) -> bool:
    stripped = decoded.strip()
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    try:
        json.loads(stripped)
        return True
    except ValueError:
        return False