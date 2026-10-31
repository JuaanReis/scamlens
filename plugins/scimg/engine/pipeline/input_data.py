from pathlib import Path
from stat import S_ISREG
from plugins.scimg import config

DEFAULT_LIMIT = 30_000_000

def error(kind, message):
    return {"status": "error", "error": {"type": kind, "message": message}}

def validate_input(ctx):
    limit = int(config.get("scanner", {}).get("max_file_size_bytes", DEFAULT_LIMIT))
    source = ctx.source
    if type(source) is bytes:
        if not source:
            return error("empty_input", "Conteúdo vazio")
        if len(source) > limit:
            return error("size_exceeded", "Imagem excede limite de bytes")
        if not ctx.file_hint:
            return error("missing_filename_hint", "file_hint é obrigatório para bytes")
        return None
    if not isinstance(source, Path):
        return error("invalid_type", "Esperado pathlib.Path ou bytes")
    try:
        stat = source.stat()
        if not S_ISREG(stat.st_mode):
            return error("unsupported_file_type", "Somente arquivos regulares")
        if stat.st_size == 0:
            return error("empty_input", "Arquivo vazio")
        if stat.st_size > limit:
            return error("size_exceeded", "Imagem excede limite de bytes")
    except OSError:
        return error("invalid_path", "Arquivo inacessível")
    return None
