"""Heurística low_edge_density: mede edge_density; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='low_edge_density', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'edges'], group='texture')
def low_edge_density(features: dict, threshold: float = 0.035, span: float = 0.035) -> ResultBase:
    return evaluate_metric(features, key='edge_density', direction='low',
                           threshold=threshold, span=span)
