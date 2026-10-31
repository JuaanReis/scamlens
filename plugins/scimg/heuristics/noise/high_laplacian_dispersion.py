"""Heurística high_laplacian_dispersion: mede laplacian_variation; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='high_laplacian_dispersion', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'laplacian'], group='noise')
def high_laplacian_dispersion(features: dict, threshold: float = 0.31, span: float = 0.24) -> ResultBase:
    return evaluate_metric(features, key='laplacian_variation', direction='high',
                           threshold=threshold, span=span)
