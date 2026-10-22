import re
from .registry import register
from .common import finding, location_flags


def _locations(ctx):
    return ctx.target.structure["locations"]


@register("missing_dynamic_location", "location", "high", 6.0, ("dynamic", "location"))
def missing_dynamic_location(ctx):
    data = ctx.target.structure
    return finding(data["dynamic"] and not data["account"].get("25"), "Location dinâmica vazia.", ["Subcampo 26-51.25 vazio."])


@register("missing_recurrence_location", "location", "high", 6.0, ("recurrence",))
def missing_recurrence_location(ctx):
    extras = ctx.target.structure["extras"]
    return finding(any(not item["fields"].get("25") for item in extras), "Template Pix de recorrência sem location.", ["Campo 80-99.25 ausente."])


@register("invalid_location_syntax", "location", "high", 6.0, ("url", "location"))
def invalid_location_syntax(ctx):
    invalid = [i for i, loc in enumerate(_locations(ctx), 1) if not loc["valid_syntax"]]
    return finding(bool(invalid), "Location com sintaxe inválida.", ["Locations inválidas: " + ", ".join(map(str, invalid))] if invalid else [])


@register("location_scheme_prefix", "location", "medium", 4.0, ("url", "format"))
def location_scheme_prefix(ctx):
    invalid = [loc for loc in _locations(ctx) if loc["supplied_scheme"]]
    return finding(bool(invalid), "BR Code exige location sem prefixo de protocolo.", ["Prefixo de protocolo encontrado."])


@register("insecure_location_scheme", "location", "high", 6.0, ("url", "https"))
def insecure_location_scheme(ctx):
    invalid = [loc for loc in _locations(ctx) if loc["scheme"] != "https"]
    return finding(bool(invalid), "Location indica acesso por protocolo diferente de HTTPS.", ["Esquema de URL não HTTPS."])


@register("unsafe_location_authority", "location", "high", 6.5, ("url", "security"))
def unsafe_location_authority(ctx):
    bad = [loc for loc in _locations(ctx) if loc["has_credentials"] or loc["port"] not in (None, 443) or any(c in loc["raw"] for c in ("\\", "\n", "\r", "\t"))]
    return finding(bool(bad), "Location possui credenciais, porta incomum ou caracteres perigosos.", ["Autoridade/endereço suspeito."])


@register("private_or_ip_location", "location", "high", 7.0, ("url", "private", "ssrf"))
def private_or_ip_location(ctx):
    bad = [loc for loc in _locations(ctx) if location_flags(loc)["private"] or location_flags(loc)["ip"]]
    return finding(bool(bad), "Location aponta para IP literal ou nome não público.", ["Location incompatível com hostname público de PSP."])


@register("malformed_location_host", "location", "high", 5.0, ("dns", "location"))
def malformed_location_host(ctx):
    bad = [loc for loc in _locations(ctx) if location_flags(loc)["invalid_host"]]
    return finding(bool(bad), "Hostname da location inválido.", ["Hostname fora do formato DNS esperado."])


@register("overlong_location", "location", "high", 5.0, ("url", "limit"))
def overlong_location(ctx):
    bad = [loc for loc in _locations(ctx) if len(loc["raw"]) > 77]
    return finding(bool(bad), "Location excede 77 caracteres.", ["Limite de 77 caracteres ultrapassado."])


@register("location_query_or_fragment", "location", "medium", 3.5, ("url", "structure"))
def location_query_or_fragment(ctx):
    bad = [loc for loc in _locations(ctx) if loc["query"] or loc["fragment"] or "?" in loc["raw"] or "#" in loc["raw"]]
    return finding(bool(bad), "Location não segue estrutura host/caminho/token.", ["Query ou fragmento detectado."])


@register("suspicious_location_host", "location", "low", 2.0, ("url", "obfuscation"))
def suspicious_location_host(ctx):
    bad = []
    for loc in _locations(ctx):
        host = loc["host"] or ""
        labels = host.split(".")
        if any(label.startswith("xn--") for label in labels) or host.count("-") >= 5:
            bad.append(host)
    return finding(bool(bad), "Hostname apresenta padrões que merecem revisão.", ["IDN/punycode ou muitos hífens."])


@register("weak_location_token", "location", "low", 2.0, ("url", "entropy"))
def weak_location_token(ctx):
    bad = []
    for loc in _locations(ctx):
        token = loc["path"].rstrip("/").split("/")[-1]
        if not token or len(token) < 8 or re.fullmatch(r"(.)\1{7,}", token):
            bad.append(loc["host"] or "<sem host>")
    return finding(bool(bad), "Token da location é curto ou previsível.", ["Location(s) com token pouco robusto."])
