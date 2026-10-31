"""Heurística low_saturation_mean: mede saturation_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='low_saturation_mean', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'saturation'], group='color')
def low_saturation_mean(features: dict, threshold: float = 0.06, span: float = 0.05) -> ResultBase:
    return evaluate_metric(features, key='saturation_mean', direction='low',
                           threshold=threshold, span=span)
