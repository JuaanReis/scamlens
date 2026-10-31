"""Heurística inconsistent_patch_residual: mede residual_tile_cv; sinal experimental não calibrado."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register
from .._metric_rule import evaluate_metric

@register(name='inconsistent_patch_residual', category='noise', severity="low", weight=1.0,
          tags=["image", 'noise', "experimental", 'patch_noise'], group='noise')
def inconsistent_patch_residual(features: dict, threshold: float = 0.42, span: float = 0.4) -> ResultBase:
    return evaluate_metric(features, key='residual_tile_cv', direction='high',
                           threshold=threshold, span=span)
