"""Heurística suspicious_repeated_columns: mede column_repetition; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='suspicious_repeated_columns', category='geometry', severity="low", weight=1.0,
          tags=["image", 'geometry', "experimental", 'duplication'], group='geometry')
def suspicious_repeated_columns(features: dict, threshold: float = 0.12, span: float = 0.5) -> ResultBase:
    return evaluate_metric(features, key='column_repetition', direction='high',
                           threshold=threshold, span=span)
