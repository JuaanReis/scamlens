from pathlib import Path
from ...parsers import parse_pix, ParseError
from ...heuristics.common import AMOUNT

_EXPECTED_KEYS = {"merchant_name", "key", "amount", "txid", "location_host"}


def collect_target_data(ctx, source: str | bytes | Path, settings, *, name=None, expected=None):
    """Aceita texto, bytes ou Path explícito; nunca interpreta texto como caminho."""
    if isinstance(source, Path):
        with source.open("rb") as handle:
            data = handle.read(settings.max_payload_bytes + 1)
        ctx.target.name = name or source.name
    elif isinstance(source, bytes):
        data = source
        ctx.target.name = name or "pix"
    elif isinstance(source, str):
        data = source.encode("utf-8")
        ctx.target.name = name or "pix"
    else:
        raise ParseError("source deve ser um payload, bytes ou pathlib.Path")

    if len(data) > settings.max_payload_bytes:
        raise ParseError("payload excede limite de bytes", "payload_too_large")
    try:
        payload = data.decode("utf-8").strip()
    except UnicodeError as error:
        raise ParseError("payload não é UTF-8 válido") from error
    if not payload or len(payload) > settings.max_payload_chars:
        raise ParseError("payload vazio ou excede limite de caracteres", "payload_too_large")
    if any(ord(c) < 32 or ord(c) == 127 for c in payload):
        raise ParseError("payload contém controles fora do formato BR Code")
    if expected is None:
        expected = {}
    if not isinstance(expected, dict):
        raise ParseError("expected deve ser um dicionário")
    unknown = set(expected) - _EXPECTED_KEYS
    if unknown:
        raise ParseError("expectativas desconhecidas: " + ", ".join(sorted(map(str, unknown))))
    if any(not isinstance(v, str) or not v or len(v) > 256 for v in expected.values()):
        raise ParseError("expectativas devem ser strings não vazias de até 256 caracteres")
    if "amount" in expected and not AMOUNT.fullmatch(expected["amount"]):
        raise ParseError("expected.amount deve ser um número decimal positivo com até duas casas")
    if "location_host" in expected:
        host = expected["location_host"]
        if "://" in host or "/" in host or "@" in host or not host.strip("."):
            raise ParseError("expected.location_host deve ser somente o hostname de referência")
    ctx.target.expectations = expected.copy()
    ctx.target.set_payload(payload)
    ctx.target.structure = parse_pix(payload)
