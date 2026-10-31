"""Heurística weak_edge_strength: mede edge_strength; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='weak_edge_strength', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'edges'], group='texture')
def weak_edge_strength(features: dict, threshold: float = 0.028, span: float = 0.025) -> ResultBase:
    return evaluate_metric(features, key='edge_strength', direction='low',
                           threshold=threshold, span=span)
