"""Heurística very_low_laplacian: mede laplacian_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='very_low_laplacian', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'laplacian'], group='noise')
def very_low_laplacian(features: dict, threshold: float = 0.01, span: float = 0.008) -> ResultBase:
    return evaluate_metric(features, key='laplacian_mean', direction='low',
                           threshold=threshold, span=span)
