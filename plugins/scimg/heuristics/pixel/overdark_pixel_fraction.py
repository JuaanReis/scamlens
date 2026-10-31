"""Heurística overdark_pixel_fraction: mede dark_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='overdark_pixel_fraction', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'clipping'], group='pixel')
def overdark_pixel_fraction(features: dict, threshold: float = 0.55, span: float = 0.4) -> ResultBase:
    return evaluate_metric(features, key='dark_fraction', direction='high',
                           threshold=threshold, span=span)
