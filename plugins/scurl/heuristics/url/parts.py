from plugins.scurl.datasets.keywords.shortener import shorten
from urllib.parse import parse_qs, unquote
from plugins.math.jaccard_similarity import similarity_jaccard
from plugins.math.shannon_entropy import shannon_entropy
from plugins.scurl.models.result_base import ResultBase
from plugins.math.value_normalizator import minmax
from re import IGNORECASE, compile
from ..registry import register

HASH_PATTERN = compile(r'^[A-Za-z0-9]{8,}$')

def looks_like_hash(segment: str) -> bool:
    base = segment.split('.')[0]
    if not HASH_PATTERN.match(base):
        return False
    
    has_case_mix = any(c.isupper() for c in base) and any(c.islower() for c in base)
    has_digits = any(c.isdigit() for c in base)
    is_only_lower = base.islower()
    
    if has_case_mix and has_digits:
        return True
    
    if is_only_lower and len(base) >= 8:
        unique_ratio = len(set(base)) / len(base)
        return unique_ratio > 0.6 
    
    return False

@register(name="random_path_risk", category="url", severity="medium", weight=3.0, tags=["url", "path", "entropy"])
def random_path_risk(structure: dict, threshold: float = 3.2, length: int = 6) -> ResultBase:
    """
    Avalia o risco de segmentos do caminho (path) serem gerados aleatoriamente
    baseado na entropia de Shannon e padrões de hash. Caminhos maliciosos
    frequentemente usam sequências aleatórias de caracteres para evitar detecção.

    Atributos:
        - structure (dict): Estrutura contendo informações sobre o caminho da URL.
        - threshold (float): Limite de entropia para considerar um segmento suspeito. Padrão: 3.2.
        - length (int): Comprimento mínimo do segmento para análise. Padrão: 6.

    Retorna:
        - ResultBase: Objeto contendo score normalizado e detalhes sobre segmentos suspeitos.
    """

    path = structure.get("path", "")
    segments = [s for s in path.split("/") if s]
    total_segments = len(segments)

    if not segments:
        return ResultBase(value=0, normalized=None, details={})

    sus_segments = []
    entropies = []

    for segment in segments:
        if segment.lower().isdigit():
            continue

        entropy = shannon_entropy(segment) 
        is_hash = looks_like_hash(segment)

        if (len(segment) >= length and entropy > threshold) or is_hash:
            sus_segments.append(segment)
            entropies.append(entropy * (1.3 if is_hash else 1.0))

    count = len(sus_segments)

    if count == 0:
        return ResultBase(
            value=0,
            normalized=None,
            details={
                "suspicious_segments": [],
                "total_segments": total_segments,
                "avg_entropy": 0
            }
        )

    avg_entropy = sum(entropies) / count
    soft_score = count / (count + 1.5)
    intensity = min(avg_entropy / 4.5, 1.2)
    normalized = min(soft_score * intensity, 1.0)

    return ResultBase(
        value=count,
        normalized=round(normalized, 2),
        details={
            "suspicious_segments": sus_segments,
            "total_segments": total_segments,
            "avg_entropy": round(avg_entropy, 2)
        }
    )

@register(name="query_no_value", category="url", severity="low", weight=1.5, tags=["url", "query", "parameter"])
def query_no_value(structure: dict) -> ResultBase:
    query = structure.get("query", "")

    if not query:
        return ResultBase(
            value=None, 
            normalized=None, details={
                "query": query
            }
        )

    empty_params = []
    for param in query.split("&"):
        if "=" in param:
            key, _, value = param.partition("=")
            if key and not value:  
                empty_params.append(key)
        else:
            if param:  
                empty_params.append(param)

    count = len(empty_params)
    normalized = min(count / 3, 1.0)  

    return ResultBase(
        value=count,
        normalized=round(normalized, 4) if normalized > 0 else None,
        details={
            "query": query, 
            "empty_params": empty_params
        }
    )

URL_PATTERN = compile(
    r'(https?://[^\s]{8,})'        
    r'|(/[a-z0-9/_\-]{3,})'          
    r'|([a-z0-9\-]+\.[a-z]{2,}/)',   
    IGNORECASE
)

@register(name="query_contains_url", category="url", severity="high", weight=4.0, tags=["url", "query", "ssrf"])
def query_contains_url(structure: dict) -> ResultBase:
    """
        Verifica se os parâmetros da query string contêm URLs. Parâmetros que contêm URLs podem indicar tentativas de open redirect, SSRF (Server-Side Request Forgery) ou outras vulnerabilidades. A função decodifica os valores dos parâmetros e verifica se algum começa com "http://" ou "https://".

        Atributos:
            - structure (dict): Estrutura contendo informações sobre a query string da URL.

        Retorna:
            - ResultBase: Um objeto contendo a URL encontrada (se houver), normalização baseada no comprimento da URL, e detalhes sobre o valor original e decodificado.

        Exemplo:
            structure = {
                "query": "redirect=http%3A//malicious.com&param=value"
            }
            result = query_contains_url(structure)
            print(result.value)  # Output: "http://malicious.com"
            print(result.normalized)  # Output: 0.22
            print(result.details)  # Output: {'original': 'http%3A//malicious.com', 'decoded': 'http://malicious.com'}
    """

    query = structure.get("query", "")
    params = parse_qs(query) if isinstance(query, str) else query

    for key, values in params.items():
        for value in values:
            decoded = unquote(value).strip()
            match = URL_PATTERN.search(decoded)

            if match:
                is_full_url = bool(match.group(1))
                normalized = 0.9 if is_full_url else 0.5

                return ResultBase(
                    value=decoded,
                    normalized=normalized,
                    details={
                        "param": key,
                        "original": value,
                        "decoded": decoded,
                        "is_full_url": is_full_url
                    }
                )

    return ResultBase(
        value=None, 
        normalized=None, 
        details={
            "query": query
        }
    )

@register(name="shorteners_keyword_risk", category="url", severity="medium", weight=3.0, tags=["url", "shortener", "phishing"])
def shorteners_keyword_risk(structure: dict, threshold: float = 0.75) -> dict:
    """
        Avalia o risco de o hostname corresponder a serviços de encurtamento de URLs. URLs encurtadas podem esconder destinos maliciosos e são frequentemente usadas em campanhas de phishing. A função compara o hostname com uma lista conhecida de encurtadores usando similaridade Jaccard.

        Atributos:
            - structure (dict): Estrutura contendo informações sobre o hostname da URL.
            - threshold (float): Limite de similaridade Jaccard para considerar uma correspondência suspeita. O valor padrão é 0.75.

        Retorna:
            - ResultBase: Um objeto contendo a contagem de encurtadores suspeitos encontrados, normalização baseada no total de encurtadores conhecidos, e detalhes sobre os encurtadores identificados.

        Exemplo:
            structure = {
                "hostname": "bitly.com"
            }
            result = shorteners_keyword_risk(structure)
            print(result.value)  # Output: 1
            print(result.normalized)  # Output: 0.02 (dependendo do tamanho da lista)
            print(result.details)  # Output: {'suspicious_shorteners': ['bit.ly']}
    """

    hostname = structure["hostname"]
    sus_shorteners = []

    for keyword in shorten:
        if similarity_jaccard(hostname, keyword) >= threshold:
            sus_shorteners.append(keyword)

    normalized = minmax(len(sus_shorteners), 0, len(shorten))

    return ResultBase(
        value = len(sus_shorteners),
        normalized = normalized if normalized != 0 else None,
        details = {
            "suspicious_shorteners": sus_shorteners
        }
    )

@register(name="length_domain", category="url", severity="low", weight=1.0, tags=["url", "domain", "length"])
def length_domain(structure: dict, threshold: float = 20, max_len: int = 50) -> dict:
    """
        Verifica o comprimento do domínio registrado. Domínios muito longos podem indicar tentativas de ofuscação ou criação de domínios únicos para evitar detecção. A função mede o comprimento total do domínio e o normaliza em uma escala de 0-100.

        Atributos:
            - structure (dict): Estrutura contendo informações sobre o domínio registrado.
            - threshold (float): Limite de comprimento para referência (não usado diretamente na normalização). O valor padrão é 20.

        Retorna:
            - ResultBase: Um objeto contendo o comprimento do domínio, normalização baseada na escala 0-100, e detalhes sobre o threshold usado.

        Exemplo:
            structure = {
                "domain_length": 35
            }
            result = length_domain(structure)
            print(result.value)  # Output: 35
            print(result.normalized)  # Output: 0.35
            print(result.details)  # Output: {'threshold': 20}
    """
    domain_length = structure.get("registered_domain_length", 0)

    if domain_length < threshold:
        return ResultBase(
            value=domain_length,
            normalized=None,
            details={"domain_length": domain_length, "threshold": threshold}
        )

    normalized = minmax(domain_length, threshold, max_len)

    return ResultBase(
        value=domain_length,
        normalized=round(normalized, 4),
        details={"domain_length": domain_length, "threshold": threshold}
    )

@register(name="length_path", category="url", severity="medium", weight=2.5, tags=["url", "path", "length"])
def length_path(structure: dict, threshold: int = 25) -> dict:
    """
        Verifica o comprimento dos segmentos do caminho (path) da URL. Segmentos muito longos no caminho podem indicar tentativas de injeção de código, exploração de vulnerabilidades ou ofuscação. A função identifica segmentos que excedem o limite de comprimento especificado.

        Atributos:
            - structure (dict): Estrutura contendo informações sobre o caminho da URL.
            - threshold (int): Limite de comprimento para considerar um segmento suspeito. O valor padrão é 25.

        Retorna:
            - ResultBase: Um objeto contendo a contagem de segmentos grandes, normalização baseada na proporção de segmentos grandes, e detalhes sobre os segmentos identificados.

        Exemplo:
            structure = {
                "path": "/normal/very_long_segment_that_exceeds_threshold/short"
            }
            result = length_path(structure)
            print(result.value)  # Output: 1
            print(result.normalized)  # Output: 0.33
            print(result.details)  # Output: {'big_paths': ['very_long_segment_that_exceeds_threshold'], 'total_paths': 3}
    """
    path = structure.get("path", "")
    paths = [p for p in path.split("/") if p]
    big_path = []
    
    for p in paths:
        if len(p) >= threshold:
            big_path.append(p)

    normalized = minmax(len(big_path), 0, len(paths))

    return ResultBase(
        value = len(big_path),
        normalized = normalized if normalized != 0 else None,
        details = {
            "big_paths": big_path,
            "total_paths": len(paths)
        }
    )

@register(name="path_depth_risk", category="url", severity="low", weight=1.5, tags=["url", "path", "depth"])
def path_depth_risk(structure: dict, threshold: int = 5) -> ResultBase:
    """
        Verifica a profundidade do caminho (path) da URL baseada na quantidade de segmentos separados por "/". Caminhos muito profundos podem indicar tentativas de exploração de vulnerabilidades em sistemas de arquivos ou APIs, ou simplesmente URLs excessivamente complexas que podem ser suspeitas.

        Atributos:
            - structure (dict): Estrutura contendo informações sobre o caminho da URL.
            - threshold (int): Limite de profundidade para considerar o caminho suspeito. O valor padrão é 5.

        Retorna:
            - ResultBase: Um objeto contendo a profundidade calculada, normalização baseada no threshold (0 se abaixo do limite, valor normalizado se acima), e detalhes sobre a profundidade e threshold.

        Exemplo:
            structure = {
                "path": "/level1/level2/level3/level4/level5/level6"
            }
            result = path_depth_risk(structure)
            print(result.value)  # Output: 6
            print(result.normalized)  # Output: 0.2 (6/5 = 1.2, normalizado para 0-1 escala seria 1, mas minmax usa 0-threshold)
            print(result.details)  # Output: {'depth': 6, 'threshold': 5}
    """
    path = structure.get("path", "")
    depth = len([p for p in path.split("/") if p])

    normalized = minmax(depth, threshold, threshold * 2) if depth > threshold else 0.0

    return ResultBase(
        value = depth,
        normalized = normalized if normalized != 0 else None,
        details = {
            "depth": depth,
            "threshold": threshold
        }
    )

@register(name="fragment_risk", category="url", severity="low", weight=1.0, tags=["url", "fragment", "entropy"])
def fragment_risk(structure: dict, entropy_threshold: float = 4.0) -> ResultBase:
    """
        Avalia o risco do fragmento (parte após #) da URL baseado na entropia de Shannon. Fragmentos com alta entropia podem indicar dados ofuscados ou tentativas de injeção. A função calcula a entropia do fragmento e a normaliza em uma escala de 0 ao threshold especificado.

        Atributos:
            - structure (dict): Estrutura contendo informações sobre o fragmento da URL.
            - threshold (int): Limite máximo para normalização da entropia. O valor padrão é 20.

        Retorna:
            - ResultBase: Um objeto contendo o valor da entropia calculada, normalização baseada no threshold, e detalhes sobre o fragmento, entropia e threshold usado.

        Exemplo:
            structure = {
                "fragment": "randomData123abc"
            }
            result = fragment_risk(structure)
            print(result.value)  # Output: 4.2
            print(result.normalized)  # Output: 0.21
            print(result.details)  # Output: {'fragment': 'randomData123abc', 'entropy': 4.2, 'threshold': 20}
    """

    fragment = structure.get("fragment", "")
    
    if not fragment:
        return ResultBase(
            value=0, 
            normalized=None, 
            details={
                "error": "No fragment found in structure"
            }
        )

    entropy = shannon_entropy(fragment)
    length = len(fragment)
    entropy_score = minmax(entropy, 2.5, 4.5)
    length_factor = 1.2 if length > 30 else 1.0
    
    normalized = min(entropy_score * length_factor, 1.0)

    return ResultBase(
        value = round(entropy, 2),
        normalized = round(normalized, 2) if normalized != 0 else None,
        details = {
            "fragment_length": length,
            "entropy": round(entropy, 2),
            "is_complex": entropy > entropy_threshold
        }
    )