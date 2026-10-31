"""Heurística nonuniform_tile_variance: mede tile_variance_cv; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='nonuniform_tile_variance', category='texture', severity="low", weight=1.0,
          tags=["image", 'texture', "experimental", 'tile_variance'], group='texture')
def nonuniform_tile_variance(features: dict, threshold: float = 0.48, span: float = 0.42) -> ResultBase:
    return evaluate_metric(features, key='tile_variance_cv', direction='high',
                           threshold=threshold, span=span)
