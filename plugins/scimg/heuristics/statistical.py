"""Indicadores experimentais mensuráveis; thresholds NÃO treinados nem calibrados.

Todas as regras seguem registro/ResultBase do scurl e usam cache de métricas.
As verificações detectam extremos e artefatos, não identificam autoria por si só.
"""
from plugins.scimg.models.result_base import ResultBase
from .registry import register

# (id, métrica medida, direção, threshold, escala, categoria, grupo)
# Valores iniciais conservadores e revisáveis via scimg.rules.<nome>.parameters.
SPECS = (
    # Distribuição de luminância (9)
    ("abnormally_dark", "luma_mean", "low", .13, .10, "pixel", "luminosity"),
    ("abnormally_bright", "luma_mean", "high", .87, .10, "pixel", "luminosity"),
    ("weak_luma_contrast", "luma_std", "low", .12, .12, "pixel", "contrast"),
    ("extreme_luma_contrast", "luma_std", "high", .66, .15, "pixel", "contrast"),
    ("overdark_pixel_fraction", "dark_fraction", "high", .55, .4, "pixel", "clipping"),
    ("overbright_pixel_fraction", "bright_fraction", "high", .55, .4, "pixel", "clipping"),
    ("extreme_clipping", "clipped_fraction", "high", .2, .5, "pixel", "clipping"),
    ("luma_dynamic_range_collapse", "luma_range", "low", .19, .18, "pixel", "contrast"),
    ("luma_histogram_peak", "hist_mode", "high", .16, .3, "pixel", "histogram"),
    # Histograma de cor (8)
    ("low_palette_diversity", "unique_color_ratio", "low", .10, .10, "color", "palette"),
    ("palette_quantization", "luma_occupancy", "low", .24, .20, "color", "palette"),
    ("high_saturation_mean", "saturation_mean", "high", .77, .2, "color", "saturation"),
    ("low_saturation_mean", "saturation_mean", "low", .06, .05, "color", "saturation"),
    ("high_saturation_spread", "saturation_std", "high", .36, .18, "color", "saturation"),
    ("extreme_saturated_area", "saturated_fraction", "high", .48, .48, "color", "saturation"),
    ("mostly_grayscale", "gray_fraction", "high", .87, .12, "color", "grayness"),
    ("channel_difference_peak", "color_difference", "high", .42, .20, "color", "chroma"),
    # Bordas e padrões de textura (9)
    ("low_edge_density", "edge_density", "low", .035, .035, "texture", "edges"),
    ("high_edge_density", "edge_density", "high", .69, .25, "texture", "edges"),
    ("weak_edge_strength", "edge_strength", "low", .028, .025, "texture", "edges"),
    ("excess_edge_strength", "edge_strength", "high", .36, .3, "texture", "edges"),
    ("very_flat_tiles", "flat_tile_fraction", "high", .61, .36, "texture", "flat_regions"),
    ("abrupt_high_variance_tiles", "high_variance_tile_fraction", "high", .74, .23, "texture", "tile_variance"),
    ("nonuniform_tile_variance", "tile_variance_cv", "high", .48, .42, "texture", "tile_variance"),
    ("weak_tile_entropy", "tile_entropy_mean", "low", .23, .20, "texture", "tile_entropy"),
    ("high_tile_entropy_dispersion", "tile_entropy_std", "high", .43, .32, "texture", "tile_entropy"),
    # Ruído e resíduos locais (9)
    ("weak_high_frequency_residual", "residual_mean", "low", .012, .010, "noise", "residual"),
    ("strong_high_frequency_residual", "residual_mean", "high", .19, .15, "noise", "residual"),
    ("high_residual_dispersion", "residual_spread", "high", .24, .2, "noise", "residual_dispersion"),
    ("unusual_residual_cv", "residual_cv", "high", .50, .35, "noise", "residual_dispersion"),
    ("very_low_laplacian", "laplacian_mean", "low", .010, .008, "noise", "laplacian"),
    ("extreme_laplacian", "laplacian_mean", "high", .13, .11, "noise", "laplacian"),
    ("high_laplacian_dispersion", "laplacian_variation", "high", .31, .24, "noise", "laplacian"),
    ("inconsistent_patch_residual", "residual_tile_cv", "high", .42, .4, "noise", "patch_noise"),
    ("channel_edge_discordance", "color_edge_discordance", "high", .28, .3, "noise", "channel_edges"),
    # Estruturas espaciais e repetição (9)
    ("too_many_identical_neighbors", "adjacent_equal_fraction", "high", .45, .53, "geometry", "duplication"),
    ("suspicious_repeated_rows", "row_repetition", "high", .12, .5, "geometry", "duplication"),
    ("suspicious_repeated_columns", "column_repetition", "high", .12, .5, "geometry", "duplication"),
    ("repeated_small_tiles", "tile_repetition", "high", .18, .5, "geometry", "tile_repeat"),
    ("extreme_horizontal_symmetry", "mirror_x_similarity", "high", .96, .04, "geometry", "symmetry"),
    ("extreme_vertical_symmetry", "mirror_y_similarity", "high", .96, .04, "geometry", "symmetry"),
    ("directional_gradient_imbalance", "gradient_imbalance", "high", .23, .3, "geometry", "orientation"),
    ("stripe_row_irregularity", "stripe_row_cv", "high", .45, .5, "geometry", "striping"),
    ("stripe_column_irregularity", "stripe_col_cv", "high", .45, .5, "geometry", "striping"),
    # Frequências espaciais via DCT 8x8 sem NumPy (5)
    ("high_frequency_excess", "freq_high_band", "high", .78, .20, "frequency", "frequency_band"),
    ("low_frequency_dominance", "freq_low_band", "high", .90, .09, "frequency", "frequency_band"),
    ("single_frequency_peak", "freq_peak_ratio", "high", .78, .20, "frequency", "periodicity"),
    ("directional_frequency_imbalance", "freq_directionality", "high", .80, .19, "frequency", "directionality"),
    ("spectral_coeff_sparsity", "freq_sparsity", "high", .88, .11, "frequency", "spectral_sparse"),
    # Processamento e compressão (4)
    ("jpeg_block_boundary_excess", "jpeg_blockiness", "high", 1.65, 1.8, "compression", "jpeg"),
    ("row_processing_spike", "stripe_row_peak", "high", .60, .8, "compression", "processing"),
    ("column_processing_spike", "stripe_col_peak", "high", .60, .8, "compression", "processing"),
    ("chroma_edge_processing_anomaly", "color_edge_discordance", "high", .38, .25, "compression", "chroma_processing"),
)

def _make_rule(name, key, direction, threshold, span, category, group):
    @register(name=name, category=category, severity="low", weight=1.0,
              tags=["image", category, "experimental", group], group=category)
    def metric_check(features: dict, threshold: float = threshold, span: float = span) -> ResultBase:
        """Mede desvio relativo a limiar provisório; NÃO é probabilidade."""
        metric = features.get("metrics", {}).get(key)
        if metric is None:
            return ResultBase(value=0, normalized=None,
                              details={"reason":"metric_not_applicable", "metric":key})
        if span <= 0:
            raise ValueError("span precisa ser positivo")
        delta = (metric-threshold) if direction == "high" else (threshold-metric)
        value = max(0.0, min(1.0, delta/span))
        return ResultBase(value=float(metric), normalized=round(value, 6),
                          details={"metric":key, "observed":round(metric,6),
                                   "threshold":threshold, "direction":direction,
                                   "limitation":"Sinal estatístico inespecífico e não calibrado"})
    metric_check.__name__ = name
    return metric_check

for _spec in SPECS:
    globals()[_spec[0]] = _make_rule(*_spec)
