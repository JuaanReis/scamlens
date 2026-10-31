"""Heurística low_palette_diversity: mede unique_color_ratio; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='low_palette_diversity', category='color', severity="low", weight=1.0,
          tags=["image", 'color', "experimental", 'palette'], group='color')
def low_palette_diversity(features: dict, threshold: float = 0.1, span: float = 0.1) -> ResultBase:
    return evaluate_metric(features, key='unique_color_ratio', direction='low',
                           threshold=threshold, span=span)
