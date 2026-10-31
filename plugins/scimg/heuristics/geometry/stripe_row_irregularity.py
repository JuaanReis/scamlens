"""Heurística stripe_row_irregularity: mede stripe_row_cv; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='stripe_row_irregularity', category='geometry', severity="low", weight=1.0,
          tags=["image", 'geometry', "experimental", 'striping'], group='geometry')
def stripe_row_irregularity(features: dict, threshold: float = 0.45, span: float = 0.5) -> ResultBase:
    return evaluate_metric(features, key='stripe_row_cv', direction='high',
                           threshold=threshold, span=span)
