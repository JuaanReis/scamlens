"""Heurística high_edge_density: mede edge_density; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='high_edge_density', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'edges'], group='texture')
def high_edge_density(features: dict, threshold: float = 0.69, span: float = 0.25) -> ResultBase:
    return evaluate_metric(features, key='edge_density', direction='high',
                           threshold=threshold, span=span)
