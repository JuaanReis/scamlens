"""Heurística channel_difference_peak: mede color_difference; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='channel_difference_peak', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'chroma'], group='color')
def channel_difference_peak(features: dict, threshold: float = 0.42, span: float = 0.2) -> ResultBase:
    return evaluate_metric(features, key='color_difference', direction='high',
                           threshold=threshold, span=span)
