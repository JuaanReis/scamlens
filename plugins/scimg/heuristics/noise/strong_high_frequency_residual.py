"""Heurística strong_high_frequency_residual: mede residual_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='strong_high_frequency_residual', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'residual'], group='noise')
def strong_high_frequency_residual(features: dict, threshold: float = 0.19, span: float = 0.15) -> ResultBase:
    return evaluate_metric(features, key='residual_mean', direction='high',
                           threshold=threshold, span=span)
