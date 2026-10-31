"""Heurística directional_gradient_imbalance: mede gradient_imbalance; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='directional_gradient_imbalance', category='geometry', severity="low", weight=1.0,
          tags=["image", 'geometry', "experimental", 'orientation'], group='geometry')
def directional_gradient_imbalance(features: dict, threshold: float = 0.23, span: float = 0.3) -> ResultBase:
    return evaluate_metric(features, key='gradient_imbalance', direction='high',
                           threshold=threshold, span=span)
