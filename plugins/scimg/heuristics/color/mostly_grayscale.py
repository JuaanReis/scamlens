"""Heurística mostly_grayscale: mede gray_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='mostly_grayscale', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'grayness'], group='color')
def mostly_grayscale(features: dict, threshold: float = 0.87, span: float = 0.12) -> ResultBase:
    return evaluate_metric(features, key='gray_fraction', direction='high',
                           threshold=threshold, span=span)
