"""Parser TLV/BR Code; não executa URLs nem consulta chaves DICT."""
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from urllib.parse import urlsplit
from .common import ParseError


@dataclass(frozen=True)
class TLV:
    tag: str
    value: str
    start: int
    end: int


def parse_tlv(data: str, *, max_fields: int = 100) -> list[TLV]:
    """Preserva posições para verificar CRC e detecta campos repetidos."""
    items = []
    offset = 0
    seen = set()
    while offset < len(data):
        if len(items) >= max_fields:
            raise ParseError("limite de objetos TLV excedido")
        if offset + 4 > len(data):
            raise ParseError("cabeçalho TLV truncado")
        header = data[offset:offset + 4]
        if not header.isascii() or not all("0" <= c <= "9" for c in header):
            raise ParseError("cabeçalho TLV inválido")
        tag, size = header[:2], int(header[2:4])
        if tag in seen:
            raise ParseError("campo TLV duplicado: " + tag)
        end = offset + 4 + size
        if end > len(data):
            raise ParseError("comprimento TLV excede o payload: " + tag)
        items.append(TLV(tag, data[offset + 4:end], offset, end))
        seen.add(tag)
        offset = end
    return items


def crc16(data: bytes) -> str:
    """CRC-16/CCITT-FALSE: polinômio 0x1021, inicial 0xFFFF."""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = (((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)) & 0xFFFF
    return f"{crc:04X}"


def _nested(value: str) -> dict[str, str]:
    return {item.tag: item.value for item in parse_tlv(value)}


def _parse_location(raw: str | None) -> dict | None:
    if raw is None:
        return None
    # URLs BR Code são codificadas sem esquema; o parser ainda observa esquemas indevidos.
    try:
        supplied_scheme = "://" in raw
        parsed = urlsplit(raw if supplied_scheme else "https://" + raw)
        host = parsed.hostname
        port = parsed.port  # pode disparar ValueError para porta malformada
    except ValueError:
        return {"raw": raw, "valid_syntax": False, "host": None, "scheme": None,
                "supplied_scheme": "://" in raw, "has_credentials": False,
                "port": None, "path": "", "query": "", "fragment": ""}
    return {
        "raw": raw,
        "valid_syntax": bool(host),
        "scheme": parsed.scheme.lower(),
        "supplied_scheme": supplied_scheme,
        "host": host.lower() if host else None,
        "has_credentials": parsed.username is not None or parsed.password is not None,
        "port": port,
        "path": parsed.path,
        "query": parsed.query,
        "fragment": parsed.fragment,
    }


def parse_pix(payload: str) -> dict:
    """Extrai estrutura, anomalias são avaliadas pelas regras heurísticas."""
    objects = parse_tlv(payload)
    if not objects:
        raise ParseError("payload vazio")
    fields = {item.tag: item.value for item in objects}
    accounts = []
    for item in objects:
        if 26 <= int(item.tag) <= 51:
            nested = _nested(item.value)
            if nested.get("00", "").casefold() == "br.gov.bcb.pix":
                accounts.append({"tag": item.tag, "fields": nested})
    if not accounts:
        raise ParseError("nenhuma conta Pix identificada", "unsupported_format")

    extras = []
    for item in objects:
        if 80 <= int(item.tag) <= 99:
            nested = _nested(item.value)
            if nested.get("00", "").casefold() == "br.gov.bcb.pix":
                extras.append({"tag": item.tag, "fields": nested})

    first = accounts[0]["fields"]
    additional = _nested(fields["62"]) if "62" in fields else {}
    crc_item = next((item for item in objects if item.tag == "63"), None)
    crc_value = crc_item.value if crc_item else None
    crc_expected = crc16(payload[:crc_item.start + 4].encode("utf-8")) if crc_item else None
    amount = fields.get("54")
    parsed_amount = None
    if amount is not None:
        try:
            parsed_amount = Decimal(amount)
        except InvalidOperation:
            pass

    locations = [_parse_location(first.get("25"))] if "25" in first else []
    locations += [_parse_location(item["fields"].get("25")) for item in extras if "25" in item["fields"]]
    recurring = bool(extras)
    dynamic = "25" in first
    return {
        "fields": fields, "objects": objects, "accounts": accounts,
        "account": first, "extras": extras, "additional": additional,
        "crc_value": crc_value, "crc_expected": crc_expected,
        "crc_last": bool(crc_item and crc_item is objects[-1]),
        "crc_valid": bool(crc_item and crc_item is objects[-1] and crc_item.value.upper() == crc_expected),
        "amount": amount, "parsed_amount": parsed_amount,
        "type": "compound" if recurring else "dynamic" if dynamic else "static",
        "dynamic": dynamic, "recurring": recurring,
        "locations": locations,
        "key": first.get("01"), "merchant_name": fields.get("59"),
        "merchant_city": fields.get("60"), "txid": additional.get("05"),
    }
