"""Heurística luma_dynamic_range_collapse: mede luma_range; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='luma_dynamic_range_collapse', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'contrast'], group='pixel')
def luma_dynamic_range_collapse(features: dict, threshold: float = 0.19, span: float = 0.18) -> ResultBase:
    return evaluate_metric(features, key='luma_range', direction='low',
                           threshold=threshold, span=span)
