"""Heurística channel_edge_discordance: mede color_edge_discordance; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='channel_edge_discordance', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'channel_edges'], group='noise')
def channel_edge_discordance(features: dict, threshold: float = 0.28, span: float = 0.3) -> ResultBase:
    return evaluate_metric(features, key='color_edge_discordance', direction='high',
                           threshold=threshold, span=span)
