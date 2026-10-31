"""Heurística extreme_clipping: mede clipped_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='extreme_clipping', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'clipping'], group='pixel')
def extreme_clipping(features: dict, threshold: float = 0.2, span: float = 0.5) -> ResultBase:
    return evaluate_metric(features, key='clipped_fraction', direction='high',
                           threshold=threshold, span=span)
