from dataclasses import dataclass, field
from math import isfinite
from typing import Callable


@dataclass(frozen=True)
class RuleEntry:
    fn: Callable
    name: str
    category: str
    severity: str
    weight: float
    tags: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)


_REGISTRY: list[RuleEntry] = []


def register(name: str, category: str, severity: str, weight: float, tags=(), **extra):
    def decorator(fn):
        if any(rule.name == name for rule in _REGISTRY):
            raise ValueError("regra duplicada: " + name)
        if type(weight) not in (int, float) or not isfinite(weight) or weight <= 0:
            raise ValueError("peso de regra inválido")
        if category not in ("integrity", "structure", "account", "transaction", "location", "context"):
            raise ValueError("categoria de regra inválida")
        _REGISTRY.append(RuleEntry(fn, name, category, severity, weight, tuple(tags), dict(extra, group=category)))
        return fn
    return decorator


def get_rules() -> list[RuleEntry]:
    return list(_REGISTRY)
