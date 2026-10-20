from pathlib import Path
from plugins.scurl.vendor.scqr.models.scan_context import ScanContext
from plugins.scurl import __version__
from scamLens import config

def resolve_bytes(ctx: ScanContext) -> None | dict:
    src = ctx.src

    if isinstance(src, bytes):
        if len(src) > config["uploads"]["qr_max_bytes"]:
            return _error("size_exceeded", "Imagem excede o limite de bytes configurado")
        ctx.src_resolved = src
        return

    if isinstance(src, (str, Path)):
        path = Path(src)
        try:
            if path.stat().st_size > config["uploads"]["qr_max_bytes"]:
                return _error("size_exceeded", "Imagem excede o limite de bytes configurado")
        except (OSError, ValueError):
            return _error("invalid_source", "Arquivo ausente ou inacessível")

        if path.suffix.lower() == ".svg":
            try:
                from cairosvg import svg2png
            except (ImportError, OSError):
                return _error("missing_dependency", "Leitura de SVG requer CairoSVG e a biblioteca nativa Cairo")
            try:
                ctx.src_resolved = svg2png(url=str(path))
            except Exception:
                return _error("invalid_image", "Não foi possível converter o SVG")
            return

        try:
            with path.open("rb") as source:
                ctx.src_resolved = source.read(config["uploads"]["qr_max_bytes"] + 1)
            if len(ctx.src_resolved) > config["uploads"]["qr_max_bytes"]:
                return _error("size_exceeded", "Imagem excede o limite de bytes configurado")
        except OSError:
            return _error("invalid_source", "Arquivo ausente ou inacessível")
        return

    return _error("invalid_source", "Tipo de fonte inválido")


def _error(error_type: str, message: str) -> dict:
    return {
        "status": "error",
        "meta": {
            "scan_time_s": 0,
            "version": __version__,
        },
        "error": {
            "type": error_type,
            "message": message,
        },
    }
