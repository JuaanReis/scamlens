"""Heurística high_saturation_spread: mede saturation_std; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='high_saturation_spread', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'saturation'], group='color')
def high_saturation_spread(features: dict, threshold: float = 0.36, span: float = 0.18) -> ResultBase:
    return evaluate_metric(features, key='saturation_std', direction='high',
                           threshold=threshold, span=span)
