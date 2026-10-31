"""Heurística abnormally_dark: mede luma_mean; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='abnormally_dark', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'luminosity'], group='pixel')
def abnormally_dark(features: dict, threshold: float = 0.13, span: float = 0.1) -> ResultBase:
    return evaluate_metric(features, key='luma_mean', direction='low',
                           threshold=threshold, span=span)
