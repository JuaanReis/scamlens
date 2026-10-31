"""Heurística high_residual_dispersion: mede residual_spread; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='high_residual_dispersion', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'residual_dispersion'], group='noise')
def high_residual_dispersion(features: dict, threshold: float = 0.24, span: float = 0.2) -> ResultBase:
    return evaluate_metric(features, key='residual_spread', direction='high',
                           threshold=threshold, span=span)
