"""Heurística chroma_edge_processing_anomaly: mede color_edge_discordance; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='chroma_edge_processing_anomaly', category='compression', severity="low", weight=1.0,
          tags=["image", 'compression', "experimental", 'chroma_processing'], group='compression')
def chroma_edge_processing_anomaly(features: dict, threshold: float = 0.38, span: float = 0.25) -> ResultBase:
    return evaluate_metric(features, key='color_edge_discordance', direction='high',
                           threshold=threshold, span=span)
