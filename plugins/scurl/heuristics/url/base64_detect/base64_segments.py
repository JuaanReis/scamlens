from urllib.parse import unquote
from .is_base64 import is_base64, is_tracking_id
from plugins.scurl.models.result_base import ResultBase
from plugins.math.value_normalizator import minmax
from ...registry import register

@register(name="base64_segments", category="url", severity="medium", weight=3.0, tags=["url", "base64", "obfuscation"])
def base64_segments(structure: dict, min_len: int = 12, max_sus: int = 3) -> ResultBase:
    """
        Detecta segmentos da URL que possam conter strings codificadas em Base64. Isso inclui subdomínios, segmentos de caminho, parâmetros de consulta e fragmentos. O resultado é o número de segmentos suspeitos encontrados, normalizado para um valor entre 0 e max_sus, juntamente com detalhes sobre os segmentos suspeitos e o total de segmentos analisados.
        
        Atributos:
        - structure (dict): A estrutura da URL, contendo chaves como "subdomain", "path", "query" e "fragment".
        - min_len (int): O comprimento mínimo para um segmento ser considerado suspeito. Padrão é 12 caracteres.
        - max_sus (int): O número máximo de segmentos suspeitos para normalização.

        Retorna:
        - ResultBase: Um objeto contendo o número de segmentos suspeitos encontrados, normalizado, e detalhes sobre os segmentos suspeitos e o total de segmentos analisados.   

        Exemplo:
        >>> url_structure = {
        ...     "subdomain": ["dGVzdC5leGFtcGxlLmNvbQ=="],
        ...     "path": "/cGF0aC90by9yZXNvdXJjZQ==/dGVzdA==",
        ...     "query": "param1=dGVtbw==&param2=dmFsdWU=",
        ...     "fragment": "ZGF0YQ==" 
        ... }
        >>> result = base64_segments(url_structure)
        >>> print(result.value)  # Número de segmentos suspeitos encontrados
        5
    """

    segments = []

    segments += structure.get("subdomain", [])

    path = structure.get("path", "")
    if path:
        segments += [s for s in path.split("/") if s]

    query = structure.get("query", "")
    if query:
        for param in query.split("&"):
            if "=" in param:
                value = param.split("=", 1)[1]
            else:
                value = param
            segments.append(unquote(value))

    fragment = structure.get("fragment", "")
    if fragment:
        segments.append(unquote(fragment))

    sus_segments = []

    for segment in segments:

        if len(segment) < min_len:
            continue

        if is_base64(segment):
            sus_segments.append(segment)
            
        elif is_tracking_id(segment):
            sus_segments.append(segment)

    sus_count = len(sus_segments)

    normalized = minmax(sus_count, 0, max_sus)
    
    return ResultBase(
        value=sus_count,
        normalized= normalized if normalized != 0.0 else None,
        details={
            "base64_segments": sus_segments,
            "total_segments": len(segments)
        }
    )