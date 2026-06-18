from dataclasses import dataclass, field
from typing import Callable, Any

@dataclass
class RuleEntry:
    """
        Representa uma entrada de regra de heurística registrada no sistema. Cada instância contém a função da regra, seu nome, categoria, severidade, peso e tags associadas. O campo 'extra' pode armazenar informações adicionais sobre a regra, como parâmetros específicos ou descrições detalhadas.
        
        Atributos:
            - fn (Callable): A função que implementa a lógica da regra de heurística.
            - name (str): Nome único da regra de heurística.
            - category (str): Categoria da regra (por exemplo, "domain_analysis", "url_analysis").
            - severity (str): Nível de severidade da regra (por exemplo, "low", "medium", "high").
            - weight (float): Peso da regra para cálculo de risco, entre 0 e 1.
            - tags (list[str]): Lista de tags para categorizar a regra (por exemplo, ["phishing", "malware"]).
            - extra (dict[str, Any]): Dicionário para armazenar informações adicionais sobre a regra, como parâmetros específicos, descrições detalhadas ou qualquer outro dado relevante.
    """
    
    fn: Callable
    name: str
    category: str
    severity: str
    weight: float
    tags: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)

_REGISTRY: list[RuleEntry] = []

def register(name: str, category: str, severity: str, weight: float, tags: list[str] = [], **kwargs):
    """
        Decorator para registrar uma função de regra de heurística no sistema. Ele adiciona a função decorada a um registro global, associando-a com metadados como nome, categoria, severidade, peso e tags. Esses metadados são usados posteriormente para classificar e aplicar as regras durante a análise de segurança.
        
        Atributos:
            - name (str): Nome único da regra de heurística.
            - category (str): Categoria da regra (por exemplo, "domain_analysis", "url_analysis").
            - severity (str): Nível de severidade da regra (por exemplo, "low", "medium", "high").
            - weight (float): Peso da regra para cálculo de risco, entre 0 e 1.
            - tags (list[str], opcional): Lista de tags para categorizar a regra (por exemplo, ["phishing", "malware"]).
            - **kwargs: Parâmetros adicionais que podem ser usados para armazenar informações extras sobre a regra.
        
        Retorna:
            Callable: A função decorada, que é registrada no sistema.
        
        Exemplo de uso:
        ```
            @register(name="example_rule", category="url_analysis", severity="medium", weight=0.3, tags=["phishing"])
            def example_rule(url: str) -> float:
                pass
        ```
    """

    def decorator(fn: Callable) -> Callable:
        _REGISTRY.append(RuleEntry(
            fn=fn,
            name=name,
            category=category,
            severity=severity,
            weight=weight,
            tags=tags,
            extra=kwargs,
        ))
        return fn
    return decorator

def get_rules() -> list[RuleEntry]:
    return list(_REGISTRY)