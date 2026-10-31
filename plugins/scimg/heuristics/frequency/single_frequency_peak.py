"""Heurística single_frequency_peak: mede freq_peak_ratio; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='single_frequency_peak', category='frequency', severity="low", weight=1.0,
          tags=["image", 'frequency', "experimental", 'periodicity'], group='frequency')
def single_frequency_peak(features: dict, threshold: float = 0.78, span: float = 0.2) -> ResultBase:
    return evaluate_metric(features, key='freq_peak_ratio', direction='high',
                           threshold=threshold, span=span)
