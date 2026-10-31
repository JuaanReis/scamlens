"""Heurística too_many_identical_neighbors: mede adjacent_equal_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='too_many_identical_neighbors', category='geometry', severity="low", weight=1.0,
          tags=["image", 'geometry', "experimental", 'duplication'], group='geometry')
def too_many_identical_neighbors(features: dict, threshold: float = 0.45, span: float = 0.53) -> ResultBase:
    return evaluate_metric(features, key='adjacent_equal_fraction', direction='high',
                           threshold=threshold, span=span)
