"""Heurística weak_luma_contrast: mede luma_std; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='weak_luma_contrast', category='pixel', severity="low", weight=1.0,
          tags=["image", 'pixel', "experimental", 'contrast'], group='pixel')
def weak_luma_contrast(features: dict, threshold: float = 0.12, span: float = 0.12) -> ResultBase:
    return evaluate_metric(features, key='luma_std', direction='low',
                           threshold=threshold, span=span)
