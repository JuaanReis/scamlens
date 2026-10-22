import re
from .registry import register
from .common import finding, key_kind, key_checksum_valid


@register("multiple_pix_accounts", "account", "high", 5.0, ("pix", "destination"))
def multiple_pix_accounts(ctx):
    count = len(ctx.target.structure["accounts"])
    return finding(count != 1, "Quantidade inesperada de contas Pix.", [f"Contas Pix encontradas: {count}."])


@register("missing_pix_destination", "account", "high", 6.0, ("pix", "destination"))
def missing_pix_destination(ctx):
    account = ctx.target.structure["account"]
    return finding(not account.get("01") and not account.get("25"), "Conta Pix sem chave e sem location.", ["Subcampos 01 e 25 ausentes."])


@register("mixed_pix_destination", "account", "high", 6.0, ("pix", "destination"))
def mixed_pix_destination(ctx):
    account = ctx.target.structure["account"]
    return finding(bool(account.get("01")) and bool(account.get("25")), "Chave e location de cobrança misturadas na mesma conta.", ["Subcampos 01 e 25 simultâneos."])


@register("invalid_pix_key_format", "account", "high", 5.5, ("key", "format"))
def invalid_pix_key_format(ctx):
    key = ctx.target.structure["key"]
    if key is None:
        return None, "Aplicável somente a códigos com chave Pix estática.", []
    return finding(key_kind(key) == "invalid", "Chave Pix com formato não reconhecido.", ["Tipo de chave não corresponde a CPF, CNPJ, telefone, email ou EVP."])


@register("invalid_pix_key_checksum", "account", "high", 5.0, ("key", "checksum"))
def invalid_pix_key_checksum(ctx):
    key = ctx.target.structure["key"]
    valid = key_checksum_valid(key) if key else None
    if valid is None:
        return None, "Checksum só aplicável a CPF/CNPJ numéricos.", []
    return finding(not valid, "Dígitos verificadores da chave documental inválidos.", ["CPF/CNPJ numérico não passou na verificação local."])


@register("invalid_optional_fss", "account", "medium", 3.0, ("pix", "withdrawal"))
def invalid_optional_fss(ctx):
    fss = ctx.target.structure["account"].get("03")
    return finding(fss is not None and not re.fullmatch(r"[0-9]{8}", fss), "ISPB de Pix Saque deve conter 8 dígitos.", ["Subcampo 03 da conta Pix malformado."])


@register("invalid_optional_information_length", "account", "low", 1.5, ("pix", "description"))
def invalid_optional_information_length(ctx):
    description = ctx.target.structure["account"].get("02")
    invalid = description is not None and not (1 <= len(description) <= 72)
    return finding(invalid, "Informação adicional da conta Pix fora dos limites.", ["Subcampo 02 deve ter até 72 caracteres."])
