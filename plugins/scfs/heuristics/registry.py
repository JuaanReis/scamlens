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

_REGISTRY = []

def register(name, category, severity, weight, tags=(), **extra):
    def decorator(fn):
        extra.setdefault("group", category)
        if any(r.name == name for r in _REGISTRY):
            raise ValueError("duplicate rule: " + name)
        if not isfinite(weight) or weight <= 0:
            raise ValueError("weight must be positive")
        _REGISTRY.append(RuleEntry(fn, name, category, severity, weight, tuple(tags), extra))
        return fn
    return decorator

def get_rules():
    return list(_REGISTRY)
