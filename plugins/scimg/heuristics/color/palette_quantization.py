"""Heurística palette_quantization: mede luma_occupancy; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='palette_quantization', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'palette'], group='color')
def palette_quantization(features: dict, threshold: float = 0.24, span: float = 0.2) -> ResultBase:
    return evaluate_metric(features, key='luma_occupancy', direction='low',
                           threshold=threshold, span=span)
