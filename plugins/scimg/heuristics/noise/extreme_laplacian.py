"""Heurística extreme_laplacian: mede laplacian_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='extreme_laplacian', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'laplacian'], group='noise')
def extreme_laplacian(features: dict, threshold: float = 0.13, span: float = 0.11) -> ResultBase:
    return evaluate_metric(features, key='laplacian_mean', direction='high',
                           threshold=threshold, span=span)
