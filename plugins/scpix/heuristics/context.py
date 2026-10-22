from decimal import Decimal, InvalidOperation
from .registry import register
from .common import finding, identity_norm


def expected(ctx, key):
    return ctx.target.expectations.get(key)


@register("unexpected_merchant_name", "context", "medium", 5.0, ("merchant", "expected"))
def unexpected_merchant_name(ctx):
    name = expected(ctx, "merchant_name")
    if name is None:
        return None, "Nenhum recebedor de referência fornecido.", []
    actual = ctx.target.structure["merchant_name"] or ""
    return finding(identity_norm(name) != identity_norm(actual), "Nome exibido no Pix diverge do esperado.", ["Nome de referência diferente do campo 59."])


@register("unexpected_pix_key", "context", "high", 7.0, ("pix", "expected"))
def unexpected_pix_key(ctx):
    key = expected(ctx, "key")
    if key is None:
        return None, "Nenhuma chave de referência fornecida.", []
    actual = ctx.target.structure["key"]
    if actual is None:
        return None, "Pix dinâmico não contém chave; titularidade não pode ser conferida offline.", []
    return finding(actual != key, "Chave Pix diverge da chave esperada.", ["Chave de referência diferente do subcampo 01."])


@register("unexpected_amount", "context", "high", 6.0, ("payment", "expected"))
def unexpected_amount(ctx):
    amount = expected(ctx, "amount")
    if amount is None:
        return None, "Nenhum valor de referência fornecido.", []
    parsed = ctx.target.structure["parsed_amount"]
    if ctx.target.structure["amount"] is None:
        return None, "Valor não presente no BR Code; cobrança dinâmica requer consulta segura ao PSP.", []
    try:
        reference = Decimal(str(amount))
    except InvalidOperation:
        raise ValueError("expected.amount inválido")
    return finding(parsed is None or not parsed.is_finite() or reference != parsed, "Valor codificado diverge do valor esperado.", ["Divergência de montante."])


@register("unexpected_txid", "context", "medium", 4.0, ("transaction", "expected"))
def unexpected_txid(ctx):
    txid = expected(ctx, "txid")
    if txid is None:
        return None, "Nenhum txid de referência fornecido.", []
    return finding(ctx.target.structure["txid"] != txid, "Identificador da transação diverge do esperado.", ["Txid diferente do informado previamente."])


@register("unexpected_location_host", "context", "high", 7.0, ("url", "expected"))
def unexpected_location_host(ctx):
    host = expected(ctx, "location_host")
    if host is None:
        return None, "Nenhum domínio de PSP de referência fornecido.", []
    locations = ctx.target.structure["locations"]
    if not locations:
        return None, "Pix estático não tem location de PSP para comparar.", []
    return finding(any(loc["host"] != host.casefold().strip(".") for loc in locations), "Domínio da location diverge do domínio esperado.", ["Hostname de referência diferente."])
