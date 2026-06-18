from pathlib import Path
from plugins.scurl.vendor.scqr.models.scan_context import ScanContext
try:
    from cairosvg import svg2png
except (ImportError, OSError) as exc:
    svg2png = None
    CAIROSVG_ERROR = exc

def resolve_bytes(ctx: ScanContext) -> None | dict:
    src = ctx.src

    if isinstance(src, bytes):
        ctx.src_resolved = src
        return

    if isinstance(src, (str, Path)):
        path = Path(src)

        if path.suffix.lower() == ".svg":
            if svg2png is None:
                return {
                    "status": "error",
                    "meta": {
                        "scan_time_s": 0
                    },
                    "error": {
                        "type": "missing_dependency",
                        "message": (
                            str(CAIROSVG_ERROR)
                        ),
                    },
                }

            ctx.src_resolved = svg2png(url=str(path))
            return

        ctx.src_resolved = path.read_bytes()
        return

    return {
        "status": "error",
        "meta": {
            "scan_time_s": 0,
            "version": __version__,
        },
        "error": {
            "type": "invalid_source",
            "message": "Tipo de fonte inválido",
        },
    }