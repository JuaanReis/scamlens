"""Heurística weak_high_frequency_residual: mede residual_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='weak_high_frequency_residual', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'residual'], group='noise')
def weak_high_frequency_residual(features: dict, threshold: float = 0.012, span: float = 0.01) -> ResultBase:
    return evaluate_metric(features, key='residual_mean', direction='low',
                           threshold=threshold, span=span)
