from stat import S_ISBLK, S_ISFIFO, S_ISCHR, S_ISSOCK
from pathlib import Path
from typing import Optional
from ...models.scan_context import ScanContext
from time import time
from ....scfs import __version__ 

MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024 # TODO: valor provisório, definir com base em dados reais

def validate_input(ctx: ScanContext) -> Optional[dict]:
    data = ctx.source
    filename_hint = ctx.file_hint

    if isinstance(data, bytes):
        return _validate_bytes(data, filename_hint)
    if isinstance(data, Path):
        return _validate_path(data)

    return _error(
        "invalid_type",
        f"Tipo de entrada não suportado: {type(data).__name__}. Esperado Path ou bytes.",
    )

def _validate_bytes(data: bytes, filename_hint: Optional[str]) -> Optional[dict]:
    if len(data) == 0:
        return _error("empty_input", "Conteúdo vazio.")

    if len(data) > MAX_FILE_SIZE_BYTES:
        return _error(
            "size_exceeded",
            f"Conteúdo excede o limite de {MAX_FILE_SIZE_BYTES} bytes.",
        )

    if filename_hint is None:
        return _error(
            "missing_filename_hint",
            "filename_hint é obrigatório para entrada em bytes "
            "(necessário para heurísticos de extensão declarada vs real).",
        )

    return None

def _validate_path(path: Path) -> Optional[dict]:
    try:
        st = path.stat()
    except OSError as e:
        return _error("invalid_path", f"Caminho inválido ou inacessível: {path} ({e})")

    mode = st.st_mode
    if S_ISFIFO(mode) or S_ISCHR(mode) or S_ISBLK(mode) or S_ISSOCK(mode):
        return _error("unsupported_file_type", f"Tipo de arquivo não suportado (pipe/device/socket): {path}")

    if st.st_size == 0:
        return _error("empty_input", f"Arquivo vazio: {path}")

    if st.st_size > MAX_FILE_SIZE_BYTES:
        return _error(
            "size_exceeded",
            f"Arquivo excede o limite de {MAX_FILE_SIZE_BYTES} bytes.",
        )

    return None

def _error(error_type: str, message: str) -> dict:
    return {
        "status": "error",
        "meta": {
            "version": __version__,
        },
        "error": {
            "type": error_type,
            "message": message,
        },
    }