"""Heurística luma_histogram_peak: mede hist_mode; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='luma_histogram_peak', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'histogram'], group='pixel')
def luma_histogram_peak(features: dict, threshold: float = 0.16, span: float = 0.3) -> ResultBase:
    return evaluate_metric(features, key='hist_mode', direction='high',
                           threshold=threshold, span=span)
