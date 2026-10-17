from ipaddress import ip_address
from re import findall
from plugins.math.shannon_entropy import shannon_entropy
from plugins.scurl.models.result_base import ResultBase
from plugins.math.value_normalizator import minmax, normalize_counter
from .parts import looks_like_hash
from ..registry import register


@register(
    name="ip_in_url",
    category="url",
    severity="medium",
    weight=3.0,
    tags=["url", "ip", "bypass"],
)
def ip_in_url(structure: dict) -> ResultBase:
    """
    Verifica a presença de endereços IP na URL. Endereços IP em URLs podem indicar tentativas de contornar filtros de segurança ou acessar recursos de forma não convencional. A função identifica padrões de IP válidos e retorna informações sobre a presença de IPs na URL analisada.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre a URL, incluindo a URL completa.

    Retorna:
        - ResultBase: Um objeto contendo informações sobre IPs encontrados, com valor binário indicando presença de IP válido, normalização baseada na quantidade de matches, e detalhes sobre os matches encontrados.

    Exemplo:
        structure = {
            "url": "http://192.168.1.1/path"
        }
        result = ip_in_url(structure)
        print(result.result)  # Output: "192.168.1.1"
        print(result.risk)  # Output: True
    """

    host = structure.get("hostname", "")
    try:
        ip = ip_address(host)
        return ResultBase(1, 0.7, {"match": str(ip), "scope": "hostname"})
    except ValueError:
        return ResultBase(0, 0, {"scope": "hostname"})


@register(
    name="random_domain_risk",
    category="url",
    severity="medium",
    weight=3.0,
    tags=["url", "entropy", "random"],
)
def random_domain_risk(structure: dict, threshold: float = 3.5) -> ResultBase:
    """
    Avalia o risco de o domínio ser gerado aleatoriamente baseado na entropia de Shannon. Domínios maliciosos frequentemente usam sequências aleatórias de caracteres para evitar detecção e criar URLs únicas. A função analisa o domínio registrado e calcula sua entropia, identificando aqueles com alta entropia como potenciais riscos.
    Atributos:
        - structure (dict): Estrutura contendo informações sobre o domínio registrado da URL.
        - threshold (float): Limite de entropia para considerar um domínio suspeito. O valor padrão é 3.5.
    Retorna:
        - ResultBase: Um objeto contendo a entropia calculada, normalização baseada no limite, e detalhes sobre o domínio analisado e a entropia calculada.
    Exemplo:
        structure = {
            "registered_domain": "randomdomain123"
        }
        result = random_domain_risk(structure)
        print(result.value)  # Output: 4.2
        print(result.normalized)  # Output: 0.8
        print(result.details)  # Output: {'domain': 'randomdomain123', 'entropy': 4.2, 'is_above_threshold': True}
    """

    domain = structure.get("domain", "")

    if not domain:
        return ResultBase(
            value=0,
            normalized=None,
            details={"error": "No registered domain found in structure"},
        )

    entropy = shannon_entropy(domain)

    if entropy <= 2.8:
        normalized = 0.0
    elif entropy >= 4.5:
        normalized = 1.0
    else:
        normalized = (entropy - 2.8) / (4.5 - 2.8)

    return ResultBase(
        value=round(entropy, 2),
        normalized=round(normalized, 2),
        details={
            "domain": domain,
            "entropy": round(entropy, 2),
            "is_above_threshold": entropy > threshold,
        },
    )


@register(
    name="subdomain_count",
    category="url",
    severity="low",
    weight=2.0,
    tags=["url", "subdomain", "depth"],
)
def subdomain_count(structure: dict, threshold: int = 3) -> ResultBase:
    """
    Verifica a quantidade de subdomínios na URL. Um número excessivo de subdomínios pode indicar tentativas de ofuscação ou criação de domínios complexos para contornar filtros de segurança. URLs legítimas geralmente têm poucos subdomínios, enquanto URLs maliciosas podem usar muitos níveis de subdomínios para esconder sua verdadeira natureza.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre os subdomínios da URL.
        - threshold (int): Limite para considerar o número de subdomínios suspeito. O valor padrão é 3.

    Retorna:
        - ResultBase: Um objeto contendo a contagem de subdomínios, normalização baseada no limite, e detalhes sobre a contagem e os subdomínios encontrados.

    Exemplo:
        structure = {
            "subdomain_count": 4,
            "subdomain": "sub1.sub2.sub3.example.com"
        }
        result = subdomain_count(structure)
        print(result.value)  # Output: 4
        print(result.normalized)  # Output: 1
        print(result.details)  # Output: {'subdomain_count': 4, 'subdomain': 'sub1.sub2.sub3.example.com'}
    """
    domain_count = structure.get("subdomain_count", 0)
    subdomain = structure.get("subdomain", "")

    normalized = normalize_counter(domain_count, threshold)

    return ResultBase(
        value=domain_count,
        normalized=normalized if normalized != 0 else None,
        details={"subdomain_count": domain_count, "subdomain": subdomain},
    )


@register(
    name="random_subdomain_risk",
    category="url",
    severity="medium",
    weight=3.0,
    tags=["url", "subdomain", "entropy"],
)
def random_subdomain_risk(structure: dict, threshold: float = 3.5) -> ResultBase:
    """
    Avalia o risco de os subdomínios serem gerados aleatoriamente baseado na entropia de Shannon. Subdomínios maliciosos frequentemente usam sequências aleatórias de caracteres para evitar detecção e criar URLs únicas. A função analisa cada subdomínio, calcula sua entropia e identifica aqueles com alta entropia como potenciais riscos.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre os subdomínios da URL.
        - threshold (float): Limite de entropia para considerar um subdomínio suspeito. O valor padrão é 3.5.

    Retorna:
        - ResultBase: Um objeto contendo a contagem de subdomínios suspeitos, normalização baseada no limite, e detalhes sobre os subdomínios analisados e suas entropias.

    Exemplo:
        structure = {
            "subdomain": ["abc123", "def456", "example"]
        }
        result = random_subdomain_risk(structure)
        print(result.value)  # Output: 2
        print(result.normalized)  # Output: 0.67
        print(result.details)  # Output: {'suspicious_subdomains': [('abc123', 4.2), ('def456', 4.1)], 'total_subdomains': 3}
    """

    subdomain = structure.get("subdomain", [])

    if not subdomain:
        return ResultBase(
            value=None,
            normalized=None,
            details={"suspicious_subdomains": [], "total_subdomains": 0},
        )

    sus_subdomains = []
    entropies = []

    for part in subdomain:
        if not part:
            continue
        entropy = shannon_entropy(part)
        is_hash = looks_like_hash(part)

        if entropy > threshold or is_hash:
            sus_subdomains.append((part, round(entropy, 2)))
            entropies.append(entropy * (1.3 if is_hash else 1.0))

    count = len(sus_subdomains)

    if count == 0:
        return ResultBase(
            value=None,
            normalized=None,
            details={"suspicious_subdomains": [], "total_subdomains": len(subdomain)},
        )

    avg_entropy = sum(entropies) / count
    soft_score = count / (count + 0.5)
    intensity = min(avg_entropy / 4.5, 1.2)
    normalized = min(soft_score * intensity, 1.0)

    return ResultBase(
        value=count,
        normalized=round(normalized, 2) if normalized > 0 else None,
        details={
            "suspicious_subdomains": sus_subdomains,
            "total_subdomains": len(subdomain),
        },
    )
