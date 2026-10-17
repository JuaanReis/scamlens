from pathlib import Path
from plugins.scurl import __version__
from time import perf_counter
from urllib.parse import urlparse

def _error(error_type: str, message: str) -> dict:
    return {
        "status": "error",
        "meta": {"data": None, "scan_time_s": 0, "version": __version__},
        "error": {"type": error_type, "message": message},
    }

def _is_url(data: str) -> bool:
    try:
        parsed = urlparse(data)
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def validate_input_qr(data: str | bytes | Path) -> dict:
    if not data:
        return _error("empty_input", "Nenhum dado fornecido para decodificação")

    start = perf_counter()

    try:
        is_url = isinstance(data, str) and _is_url(data)
    except ValueError:
        return _error("invalid_url", "URL inválida")
    if is_url:
        return {
            "status": "ok",
            "meta": {
                "data": data,
                "scan_time_s": round(perf_counter() - start, 3),
                "version": __version__,
            },
        }

    from plugins.scurl.vendor.scqr.engine.main import run_engine

    result = run_engine(data)
    if result.get("status", {}) == "error":
        return _error("scqr_error", result.get("error", {}).get("message", ""))

    qr_type = result.get("result", {}).get("qr_code_type")
    if qr_type is None:
        return _error(
            "undetected_qr_code", "Nenhum QR code foi detectado na entrada fornecida"
        )

    if qr_type != "url":
        return _error(
            "unsupported_qr_type", f"QR code do tipo {qr_type} não é suportado"
        )

    decode = result.get("data", {}).get("decoded")
    if not decode:
        return _error(
            "empty_qr_data",
            "O QR code foi detectado, mas não contém dados decodificáveis",
        )

    return {
        "status": "ok",
        "meta": {
            "data": decode,
            "scan_time_s": round(perf_counter() - start, 3),
            "version": __version__,
        },
    }
