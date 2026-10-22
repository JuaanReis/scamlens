from .registry import register
from .common import finding


@register("missing_crc", "integrity", "high", 6.0, ("crc", "emv"))
def missing_crc(ctx):
    return finding(ctx.target.structure["crc_value"] is None, "CRC obrigatório ausente.", ["Campo 63 não encontrado."])


@register("crc_not_last", "integrity", "high", 6.0, ("crc", "emv"))
def crc_not_last(ctx):
    data = ctx.target.structure
    return finding(data["crc_value"] is not None and not data["crc_last"], "CRC deve ser o último objeto TLV.", ["Campo 63 não é o último."])


@register("crc_invalid_format", "integrity", "high", 6.0, ("crc",))
def crc_invalid_format(ctx):
    value = ctx.target.structure["crc_value"]
    invalid = value is not None and (len(value) != 4 or any(c not in "0123456789abcdefABCDEF" for c in value))
    return finding(invalid, "CRC deve conter quatro dígitos hexadecimais.", ["Formato de CRC inválido."])


@register("crc_mismatch", "integrity", "high", 7.0, ("crc", "tampering"))
def crc_mismatch(ctx):
    data = ctx.target.structure
    value = data["crc_value"]
    if value is None or not data["crc_last"] or len(value) != 4 or any(c not in "0123456789abcdefABCDEF" for c in value):
        return None, "Comparação de CRC indisponível.", []
    return finding(not data["crc_valid"], "CRC calculado não confere com o fornecido.", ["Integridade do payload não confere."])
