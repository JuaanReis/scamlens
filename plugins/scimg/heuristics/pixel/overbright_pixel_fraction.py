"""Heurística overbright_pixel_fraction: mede bright_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='overbright_pixel_fraction', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'clipping'], group='pixel')
def overbright_pixel_fraction(features: dict, threshold: float = 0.55, span: float = 0.4) -> ResultBase:
    return evaluate_metric(features, key='bright_fraction', direction='high',
                           threshold=threshold, span=span)
