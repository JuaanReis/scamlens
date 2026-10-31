"""Heurística directional_frequency_imbalance: mede freq_directionality; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='directional_frequency_imbalance', category='frequency', severity="low", weight=1.0,
          tags=["image", 'frequency', "experimental", 'directionality'], group='frequency')
def directional_frequency_imbalance(features: dict, threshold: float = 0.8, span: float = 0.19) -> ResultBase:
    return evaluate_metric(features, key='freq_directionality', direction='high',
                           threshold=threshold, span=span)
