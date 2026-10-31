"""Heurística jpeg_block_boundary_excess: mede jpeg_blockiness; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='jpeg_block_boundary_excess', category='compression', severity="low", weight=1.0,
          tags=["image", 'compression', "experimental", 'jpeg'], group='compression')
def jpeg_block_boundary_excess(features: dict, threshold: float = 1.65, span: float = 1.8) -> ResultBase:
    return evaluate_metric(features, key='jpeg_blockiness', direction='high',
                           threshold=threshold, span=span)
