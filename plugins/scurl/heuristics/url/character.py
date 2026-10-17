from plugins.scurl.models.result_base import ResultBase
from re import IGNORECASE, compile
from urllib.parse import urlparse, unquote
from plugins.math.value_normalizator import normalize_counter
from ..registry import register


@register(
    name="hyphen_risk",
    category="url",
    severity="medium",
    weight=2.5,
    tags=["url", "domain"],
)
def hyphen_risk(structure: dict, threshold: int = 2) -> ResultBase:
    """
    Verifica a quantidade de hífens no domínio registrado. Hífens são frequentemente usados em URLs maliciosas para criar domínios que se assemelham a marcas legítimas, mas com pequenas variações (ex: "pay-pal.com" em vez de "paypal.com"). Um número elevado de hífens pode indicar uma tentativa de enganar os usuários, aumentando o risco de phishing. O limite recomendado é geralmente 2 ou mais hífens, mas isso pode variar dependendo do contexto e do tipo de análise que está sendo realizada.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre a URL, incluindo a contagem de hífens.
        - threshold (int): Limite para considerar o risco elevado. O valor padrão é 2.

    Retorna:
        - ResultBase: Um objeto contendo o valor da contagem de hífens, a normalização do risco com base no limite, e detalhes adicionais sobre a contagem de hífens.

    Exemplo:
        structure = {
            "url": "http://pay-pal.com",
            "registered_domain": "pay-pal.com",
            "hyphen_count": 1
        }
        result = hyphen_risk(structure)
        print(result.value)  # Output: 1
        print(result.normalized)  # Output: 0 (considerando o limite de 2)
        print(result.details)  # Output: {'hyphen_count': 1}
    """

    hifen_count = structure.get("hyphen_count", 0)
    normalized = normalize_counter(hifen_count, threshold)

    return ResultBase(
        value=hifen_count,
        normalized=normalized if normalized != 0.0 else None,
        details={
            "hyphen_count": hifen_count,
        },
    )


@register(
    name="at_risk",
    category="url",
    severity="high",
    weight=4.0,
    tags=["url", "at", "phishing"],
)
def at_risk(structure: dict, threshold: int = 1) -> ResultBase:
    """
    Verifica a presença de caracteres "@" na URL. O caractere "@" é frequentemente usado em ataques de phishing para ocultar a verdadeira origem de uma URL. Por exemplo, em "http://paypal.com@malicious.com", o navegador ignora tudo antes do "@", levando o usuário a um site malicioso enquanto exibe "paypal.com" na barra de endereços. Um ou mais caracteres "@" indicam um risco potencial de phishing.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre a URL, incluindo a URL completa.
        - threshold (int): Limite para considerar o risco elevado. O valor padrão é 1 (qualquer presença de "@" é considerada suspeita).

    Retorna:
        - ResultBase: Um objeto contendo a contagem de caracteres "@", a normalização do risco com base no limite, e detalhes sobre a contagem.

    Exemplo:
        structure = {
            "url": "http://paypal.com@malicious.com"
        }
        result = at_risk(structure)
        print(result.value)  # Output: 1
        print(result.normalized)  # Output: 1
        print(result.details)  # Output: {'at_count': 1}
    """
    url = structure.get("url", "")
    at_count = int(urlparse(structure.get("original_url", url)).username is not None)
    normalized = normalize_counter(at_count, threshold)

    return ResultBase(
        value=at_count,
        normalized=normalized if normalized != 0.0 else None,
        details={
            "at_count": at_count,
        },
    )


@register(
    name="equal_risk",
    category="url",
    severity="medium",
    weight=2.0,
    tags=["url", "equal", "obfuscation"],
)
def equal_risk(structure: dict) -> ResultBase:
    path = structure.get("path", "")
    subdomain = structure.get("subdomain", [])
    domain = structure.get("domain", "")

    suspicious_text = path + domain + "".join(subdomain)
    equal_count = suspicious_text.count("=")

    if equal_count == 0:
        return ResultBase(value=None, normalized=None, details={"equal_count": 0})

    normalized = min(equal_count / 3, 1.0)

    return ResultBase(
        value=equal_count,
        normalized=round(normalized, 4) if normalized > 0 else None,
        details={"equal_count": equal_count},
    )


@register(
    name="num_ratio_risk",
    category="url",
    severity="medium",
    weight=2.0,
    tags=["url", "numbers", "domain"],
)
def num_ratio_risk(structure: dict, threshold: float = 0.25) -> ResultBase:
    """
    Verifica a proporção de dígitos no domínio ou subdomínios registrados. URLs maliciosas frequentemente usam muitos números para contornar filtros de segurança ou para se parecerem com endereços IP. Uma alta proporção de números em relação ao comprimento total pode indicar um domínio suspeito. O limite recomendado é 0.25 (25%), o que significa que domínios com mais de 25% de dígitos são considerados suspeitos.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre o domínio registrado e subdomínios.
        - threshold (float): Limite de proporção para considerar o risco elevado. O valor padrão é 0.25 (25%).

    Retorna:
        - ResultBase: Um objeto contendo a proporção de dígitos da parte mais longa (domínio ou subdomínio), a normalização do risco com base no limite, e detalhes sobre a razão calculada e o texto analisado.

    Exemplo:
        structure = {
            "registered_domain": "pay123pal456.com",
            "subdomain": []
        }
        result = num_ratio_risk(structure)
        print(result.value)  # Output: 0.3333
        print(result.normalized)  # Output: 1
        print(result.details)  # Output: {'ratio': 0.3333, 'analyzed': 'pay123pal456'}
    """

    domain = structure.get("hostname", "").split(".")[0]
    subdomains = structure.get("subdomain", [])

    all_parts = [domain] + subdomains
    text = max(all_parts, key=len) if all_parts else ""

    if not text:
        return ResultBase(value=None, normalized=None, details={"ratio": 0.0})

    digits = sum(c.isdigit() for c in text)
    ratio = digits / len(text)

    normalized = normalize_counter(ratio, threshold)

    return ResultBase(
        value=ratio,
        normalized=normalized if normalized != 0.0 else None,
        details={"ratio": round(ratio, 4), "analyzed": text},
    )


@register(
    name="mixed_encoding",
    category="url",
    severity="high",
    weight=4.0,
    tags=["url", "encoding", "obfuscation"],
)
def mixed_encoding(structure: dict) -> ResultBase:
    url = structure.get("url", "")

    percent_encoding = "%" in url
    punycode = "xn--" in url.lower()
    unicode_chars = any(ord(c) > 127 for c in url)

    double_encoding = "%25" in url

    techniques = sum([percent_encoding, punycode, unicode_chars, double_encoding])

    if double_encoding:
        normalized = 1.0
    elif techniques >= 2:
        normalized = 0.7
    else:
        normalized = None

    return ResultBase(
        value=techniques,
        normalized=normalized,
        details={
            "percent_encoding": percent_encoding,
            "unicode_chars": unicode_chars,
            "punycode": punycode,
            "double_encoding": double_encoding,
        },
    )


XSS_PATTERN = compile(
    r"(<script>|javascript:|onerror=|onload=|alert\(|document\.cookie|eval\()",
    IGNORECASE,
)


@register(
    name="xss_risk",
    category="url",
    severity="high",
    weight=5.0,
    tags=["url", "xss", "injection"],
)
def xss_risk(structure: dict) -> ResultBase:
    """
    Verifica a presença de indicadores de ataques XSS (Cross-Site Scripting) na URL. Essa função detecta padrões comuns usados em ataques XSS, como tags de script, manipuladores de eventos (onerror, onload), funções JavaScript perigosas (alert, eval, document.cookie) e outras técnicas de injeção de código. A presença de qualquer um desses indicadores sugere uma tentativa de executar código malicioso no navegador do usuário.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre a URL completa a ser analisada.

    Retorna:
        - ResultBase: Um objeto contendo o número de indicadores XSS encontrados, a normalização binária (0 se nenhum encontrado, 1 se algum encontrado), e detalhes sobre os indicadores detectados.

    Exemplo:
        structure = {
            "url": "http://example.com?param=<script>alert('xss')</script>"
        }
        result = xss_risk(structure)
        print(result.value)  # Output: 2
        print(result.normalized)  # Output: 1
        print(result.details)  # Output: {'found_indicators': ['<script>', "alert("]}
    """
    url = structure.get("url", "")

    found_indicators = XSS_PATTERN.findall(unquote(unquote(url)))
    normalized = int(len(found_indicators) > 0)

    return ResultBase(
        value=len(found_indicators),
        normalized=normalized if normalized != 0.0 else None,
        details={"found_indicators": found_indicators},
    )
