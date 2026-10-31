"""Heurística excess_edge_strength: mede edge_strength; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='excess_edge_strength', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'edges'], group='texture')
def excess_edge_strength(features: dict, threshold: float = 0.36, span: float = 0.3) -> ResultBase:
    return evaluate_metric(features, key='edge_strength', direction='high',
                           threshold=threshold, span=span)
