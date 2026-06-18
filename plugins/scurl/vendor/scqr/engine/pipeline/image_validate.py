from plugins.scurl.vendor.scqr.models.scan_context import ScanContext

_SIGNATURES: list[tuple[int, bytes, str]] = [
    (0, b"\xff\xd8\xff", ".jpg"),
    (0, b"\x89PNG\r\n\x1a\n", ".png"),
    (0, b"BM", ".bmp"),
    (0, b"GIF87a", ".gif"),
    (0, b"GIF89a", ".gif"),
    (0, b"II\x2a\x00", ".tiff"),
    (0, b"MM\x00\x2a", ".tiff"),
    (8, b"WEBP", ".webp"),
]

def is_qrcode(ctx: ScanContext) -> dict | None:
    if not ctx.decoded:
        return {
            "status": "error",
            "meta": {
                "scan_time_s": 0
            },
            "error": {
                "type": "QR code not detected", 
                "message": "Nenhum QR code foi detectado na imagem"
            }
        }
    return None

def detect_extension(ctx: ScanContext) -> dict | None:
    header = ctx.src_resolved

    if not header:
        return {
            "status": "error",
            "meta": {
                "scan_time_s": 0
            },
            "error": {
                "type": "invalid_image",
                "message": "Nenhum dado de imagem disponível"
            }
        }

    for offset, signature, ext in _SIGNATURES:
        end = offset + len(signature)
        if len(header) >= end and header[offset:end] == signature:
            return None

    return {
        "status": "error",
        "meta": {
            "scan_time_s": 0
        },
        "error": {
            "type": "invalid_image",
            "message": "Formato de imagem não suportado ou arquivo corrompido"
        }
    }