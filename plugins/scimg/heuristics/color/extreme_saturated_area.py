"""Heurística extreme_saturated_area: mede saturated_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='extreme_saturated_area', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'saturation'], group='color')
def extreme_saturated_area(features: dict, threshold: float = 0.48, span: float = 0.48) -> ResultBase:
    return evaluate_metric(features, key='saturated_fraction', direction='high',
                           threshold=threshold, span=span)
