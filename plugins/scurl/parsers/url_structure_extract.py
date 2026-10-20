from urllib.parse import parse_qs, urlparse
from providers.domain.structure import extract
from ipaddress import ip_address

_SUSPICIOUS_QUERY_KEYWORDS = frozenset([
    "cmd", "exec", "script", "redirect", "login", "token",
    "payload", "eval", "base64", "url", "goto", "return",
])

_RISKY_TLDS = frozenset([
    "tk", "ml", "ga", "cf", "gq", "xyz", "top", "click",
    "link", "work", "date", "racing", "online", "site",
])

def _is_ip(hostname: str) -> bool:
    try:
        ip_address(hostname)
        return True
    except ValueError:
        return False

def extract_structure(url: str):
    """
        Extrai características estruturais de uma URL para análise.

        A função recebe uma URL e retorna um dicionário com informações
        detalhadas sobre sua composição, incluindo esquema, domínio,
        porta, caminho, parâmetros de consulta e fragmento, bem como
        métricas derivadas como comprimento do URL, comprimento do domínio,
        número de subdomínios, número de hífens e contagem de parâmetros
        de consulta.

        Essas características são úteis para:
            - análise de URLs maliciosas
            - detecção de phishing e typosquatting
            - cálculo de métricas de complexidade ou entropia de URLs
            - uso em algoritmos de aprendizado de máquina que classificam URLs

        Args:
            url (str): URL que será analisada.

        Returns:
            dict: Dicionário contendo as características extraídas:
                - "url": URL original
                - "scheme": esquema (http, https)
                - "hostname": domínio principal
                - "port": porta (se especificada)
                - "path": caminho da URL
                - "params": parâmetros de rota (URL params)
                - "query": string de consulta
                - "fragment": fragmento da URL (#)
                - "url_length": comprimento total da URL
                - "domain_length": comprimento do domínio
                - "path_length": comprimento do caminho
                - "subdomain_count": quantidade de subdomínios
                - "hyphen_count": quantidade de hífens no domínio
                - "query_param_count": quantidade de parâmetros na query
                - "query_length": comprimento da string de query

            Retorna None caso a URL não possua um domínio válido.

        Exemplo:
            ```
                >>> extract_features("https://www.exemplo.com/path?arg=1#frag")
                {
                    "url": "https://www.exemplo.com/path?arg=1#frag",
                    "scheme": "https",
                    "hostname": "www.exemplo.com",
                    "port": None,
                    "path": "/path",
                    "params": "",
                    "query": "arg=1",
                    "fragment": "frag",
                    "url_length": 35,
                    "domain_length": 15,
                    "path_length": 5,
                    "subdomain_count": 2,
                    "hyphen_count": 0,
                    "query_param_count": 1,
                    "query_length": 5
                }
            ```
    """
    
    if not url:
        return None

    original_url = url

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return None

    hostname = hostname.lower()
    ext = extract(hostname)

    if not ext.domain:
        return None

    registered_domain = ext.top_domain_under_public_suffix or hostname
    tld = ext.suffix.lower() if ext.suffix else ""

    raw_subs = [s for s in ext.subdomain.split(".") if s] if ext.subdomain else []
    subs_no_www = [s for s in raw_subs if s != "www"]
    subdomain_count = len(subs_no_www)

    path = parsed.path
    query = parsed.query

    query_params = parse_qs(query, keep_blank_values=True)
    query_param_count = len(query_params)

    params_without_value = sum(
        1 for v in query_params.values() if not any(val.strip() for val in v)
    )

    query_lower = query.lower()
    query_keyword_hits = [k for k in _SUSPICIOUS_QUERY_KEYWORDS if k in query_lower]

    path_depth = len([p for p in path.split("/") if p]) if path else 0

    num_digits_in_domain = sum(c.isdigit() for c in ext.domain)
    digit_ratio_in_domain = (
        num_digits_in_domain / len(ext.domain) if ext.domain else 0.0
    )

    hyphen_count = hostname.count("-")
    has_double_hyphen = "--" in hostname  

    num_special_chars_in_path = sum(
        not c.isalnum() and c not in "/-._~" for c in path
    )

    return {
        "url":               original_url,
        "scheme":            parsed.scheme,
        "hostname":          hostname,
        "domain":            ext.domain,
        "netloc":            parsed.netloc,
        "registered_domain": registered_domain,
        "subdomain":         subs_no_www,
        "tld":               tld,
        "port":              parsed.port,
        "path":              path,
        "query":             query,
        "fragment":          parsed.fragment,
        "url_length":               len(original_url),
        "domain_length":            len(ext.domain),
        "registered_domain_length": len(registered_domain) if registered_domain else 0,
        "path_length":              len(path),
        "query_length":             len(query),
        "subdomain_count":          subdomain_count,
        "hyphen_count":             hyphen_count,
        "has_double_hyphen":        int(has_double_hyphen),
        "path_depth":               path_depth,
        "query_param_count":        query_param_count,
        "params_without_value":     params_without_value,
        "num_digits_in_domain":     num_digits_in_domain,
        "digit_ratio_in_domain":    round(digit_ratio_in_domain, 4),
        "num_special_chars_in_path": num_special_chars_in_path,
        "has_port":                 int(parsed.port is not None),
        "has_fragment":             int(bool(parsed.fragment)),
        "has_query":                int(bool(query)),
        "has_ip":                   int(_is_ip(hostname)),
        "is_https":                 int(parsed.scheme == "https"),
        "risky_tld":                int(tld in _RISKY_TLDS),
        "query_keyword_count":      len(query_keyword_hits),
        "query_has_keywords":       int(bool(query_keyword_hits)),
    }
