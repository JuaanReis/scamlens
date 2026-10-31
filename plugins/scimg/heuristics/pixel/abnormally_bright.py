"""Heurística abnormally_bright: mede luma_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='abnormally_bright', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'luminosity'], group='pixel')
def abnormally_bright(features: dict, threshold: float = 0.87, span: float = 0.1) -> ResultBase:
    return evaluate_metric(features, key='luma_mean', direction='high',
                           threshold=threshold, span=span)
