"""Mesmo contrato @register do scurl; overrides por scimg.rules do config.toml."""
from dataclasses import dataclass, field, replace
from typing import Callable
from inspect import signature
from math import isfinite
from plugins.scimg import config

@dataclass
class RuleEntry:
    fn: Callable
    name: str
    category: str
    severity: str
    weight: float
    tags: list[str] = field(default_factory=list)
    extra: dict = field(default_factory=dict)

_REGISTRY: list[RuleEntry] = []

def register(name: str, category: str, severity: str, weight: float,
             tags: list[str] | None = None, **kwargs):
    def decorator(fn):
        if any(entry.name == name for entry in _REGISTRY):
            raise ValueError(f"Heurística duplicada: {name}")
        _REGISTRY.append(RuleEntry(fn, name, category, severity, weight,
                                   list(tags or []), kwargs))
        return fn
    return decorator

def get_rules() -> list[RuleEntry]:
    options = config.get("rules", {})
    unknown = set(options) - {r.name for r in _REGISTRY}
    if unknown:
        raise ValueError(f"Regras desconhecidas na configuração: {sorted(unknown)}")
    entries = []
    for rule in _REGISTRY:
        data = options.get(rule.name, {})
        if not isinstance(data, dict):
            raise ValueError(f"Config inválida: {rule.name}")
        weight = data.get("weight", rule.weight)
        if type(weight) not in (int, float) or not isfinite(weight) or weight < 0:
            raise ValueError(f"Peso inválido: {rule.name}")
        params = dict(data.get("parameters", {}))
        signature(rule.fn).bind({}, **params)
        entries.append(replace(rule, weight=float(weight),
                               extra={**rule.extra, "parameters": params}))
    return entries
