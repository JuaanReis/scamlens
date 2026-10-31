"""Heurística column_processing_spike: mede stripe_col_peak; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='column_processing_spike', category='compression', severity="low", weight=1.0,
          tags=["image", 'compression', "experimental", 'processing'], group='compression')
def column_processing_spike(features: dict, threshold: float = 0.6, span: float = 0.8) -> ResultBase:
    return evaluate_metric(features, key='stripe_col_peak', direction='high',
                           threshold=threshold, span=span)
