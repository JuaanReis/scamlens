"""Heurística very_flat_tiles: mede flat_tile_fraction; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='very_flat_tiles', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'flat_regions'], group='texture')
def very_flat_tiles(features: dict, threshold: float = 0.61, span: float = 0.36) -> ResultBase:
    return evaluate_metric(features, key='flat_tile_fraction', direction='high',
                           threshold=threshold, span=span)
