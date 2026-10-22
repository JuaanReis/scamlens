from .registry import register
from .common import finding, DANGEROUS_UNICODE


@register("invalid_format_version", "structure", "high", 5.0, ("emv",))
def invalid_format_version(ctx):
    value = ctx.target.structure["fields"].get("00")
    return finding(value != "01", "Payload Format Indicator deve ser 01.", ["Versão ausente ou desconhecida."])


@register("missing_required_fields", "structure", "high", 6.0, ("emv", "required"))
def missing_required_fields(ctx):
    data = ctx.target.structure
    missing = [name for name in ("00", "52", "53", "58", "59", "60", "62") if not data["fields"].get(name)]
    return finding(bool(missing), "Campos obrigatórios do BR Code ausentes.", ["Ausentes: " + ", ".join(missing)] if missing else [])


@register("invalid_merchant_category", "structure", "medium", 3.0, ("emv", "merchant"))
def invalid_merchant_category(ctx):
    code = ctx.target.structure["fields"].get("52")
    invalid = code is not None and (len(code) != 4 or not code.isascii() or not code.isdigit())
    return finding(invalid, "Categoria de comerciante deve conter 4 dígitos.", ["Campo 52 malformado."])


@register("invalid_currency", "structure", "high", 5.0, ("emv", "brl"))
def invalid_currency(ctx):
    value = ctx.target.structure["fields"].get("53")
    return finding(value is not None and value != "986", "Moeda Pix deve ser 986 (BRL).", ["Moeda divergente de 986."])


@register("invalid_country", "structure", "high", 5.0, ("emv", "br"))
def invalid_country(ctx):
    value = ctx.target.structure["fields"].get("58")
    return finding(value is not None and value != "BR", "País deve ser BR.", ["Campo 58 divergente de BR."])


@register("invalid_initiation_method", "structure", "medium", 3.0, ("emv",))
def invalid_initiation_method(ctx):
    value = ctx.target.structure["fields"].get("01")
    return finding(value is not None and value not in ("11", "12"), "Point of Initiation Method desconhecido.", ["Campo 01 não é 11 ou 12."])


@register("merchant_name_length", "structure", "medium", 3.0, ("merchant",))
def merchant_name_length(ctx):
    name = ctx.target.structure["merchant_name"]
    return finding(name is not None and not (1 <= len(name) <= 25) or name is not None and not name.strip(), "Nome do recebedor deve ter entre 1 e 25 caracteres úteis.", ["Campo 59 inválido."])


@register("merchant_city_length", "structure", "medium", 3.0, ("merchant",))
def merchant_city_length(ctx):
    city = ctx.target.structure["merchant_city"]
    return finding(city is not None and (not (1 <= len(city) <= 15) or not city.strip()), "Cidade do recebedor deve ter entre 1 e 15 caracteres úteis.", ["Campo 60 inválido."])


@register("control_or_invisible_characters", "structure", "high", 5.5, ("unicode", "obfuscation"))
def control_or_invisible_characters(ctx):
    fields = ctx.target.structure["fields"]
    hits = [tag for tag in ("59", "60") if any(ord(c) < 32 or 0x7f <= ord(c) < 0xa0 or c in DANGEROUS_UNICODE or 0x202a <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069 for c in fields.get(tag, ""))]
    return finding(bool(hits), "Texto do recebedor contém controles ou caracteres invisíveis.", ["Campos afetados: " + ", ".join(hits)] if hits else [])
