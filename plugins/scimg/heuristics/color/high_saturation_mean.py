"""Heurística high_saturation_mean: mede saturation_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='high_saturation_mean', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'saturation'], group='color')
def high_saturation_mean(features: dict, threshold: float = 0.77, span: float = 0.2) -> ResultBase:
    return evaluate_metric(features, key='saturation_mean', direction='high',
                           threshold=threshold, span=span)
