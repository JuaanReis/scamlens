"""Heurística extreme_vertical_symmetry: mede mirror_y_similarity; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='extreme_vertical_symmetry', category='geometry', severity="low", weight=1.0,
          tags=["image", 'geometry', "experimental", 'symmetry'], group='geometry')
def extreme_vertical_symmetry(features: dict, threshold: float = 0.96, span: float = 0.04) -> ResultBase:
    return evaluate_metric(features, key='mirror_y_similarity', direction='high',
                           threshold=threshold, span=span)
