"""Heurística extreme_luma_contrast: mede luma_std; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='extreme_luma_contrast', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'contrast'], group='pixel')
def extreme_luma_contrast(features: dict, threshold: float = 0.66, span: float = 0.15) -> ResultBase:
    return evaluate_metric(features, key='luma_std', direction='high',
                           threshold=threshold, span=span)
