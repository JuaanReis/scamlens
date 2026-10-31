"""Heurística high_frequency_excess: mede freq_high_band; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='high_frequency_excess', category='frequency', severity="low", weight=1.0,
          tags=["image", 'frequency', "experimental", 'frequency_band'], group='frequency')
def high_frequency_excess(features: dict, threshold: float = 0.78, span: float = 0.2) -> ResultBase:
    return evaluate_metric(features, key='freq_high_band', direction='high',
                           threshold=threshold, span=span)
