"""Heurística stripe_column_irregularity: mede stripe_col_cv; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='stripe_column_irregularity', category='geometry', severity="low", weight=1.0,
          tags=["image", 'geometry', "experimental", 'striping'], group='geometry')
def stripe_column_irregularity(features: dict, threshold: float = 0.45, span: float = 0.5) -> ResultBase:
    return evaluate_metric(features, key='stripe_col_cv', direction='high',
                           threshold=threshold, span=span)
