"""Heurística low_frequency_dominance: mede freq_low_band; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='low_frequency_dominance', category='frequency', severity="low", weight=1.0,
          tags=["image", 'frequency', "experimental", 'frequency_band'], group='frequency')
def low_frequency_dominance(features: dict, threshold: float = 0.9, span: float = 0.09) -> ResultBase:
    return evaluate_metric(features, key='freq_low_band', direction='high',
                           threshold=threshold, span=span)
