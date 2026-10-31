"""Pipeline SCIMG: validate -> collect -> execute -> score -> response."""
from pathlib import Path
from math import isfinite
from plugins.scimg import config
from plugins.scimg.models.scan_context import ScanContext
from plugins.scimg.heuristics.registry import get_rules
import plugins.scimg.heuristics  # registra todas as regras
from .pipeline import validate_input, collect_image, execute_rules, calculate_score, build_response, meta_attribute, build_error_response
from .pipeline.input_data import error
from .pipeline.metadata import _hashing_data

def run_engine(source: Path | bytes, file_hint: str | None = None, *,
               k: float | None = None, score_model: str | None = None) -> dict:
    settings = config.get("scanner", {})
    k = settings.get("k", 5.0) if k is None else k
    score_model = settings.get("score_model", "grouped") if score_model is None else score_model
    if type(k) not in (float, int) or not isfinite(k) or not .1 <= k <= 20:
        raise ValueError("k deve estar entre 0.1 e 20")
    if score_model not in ("legacy", "grouped"):
        raise ValueError("score_model deve ser 'grouped' ou 'legacy'")
    ctx = ScanContext(source=source, file_hint=file_hint, image_data=source)
    if problem := validate_input(ctx):
        return problem
    try:
        ctx.content_bytes = source.read_bytes() if isinstance(source, Path) else source
    except OSError:
        return error("invalid_path", "Falha ao ler arquivo")
    if len(ctx.content_bytes) > int(settings.get("max_file_size_bytes", 30_000_000)):
        return error("size_exceeded", "Arquivo excedeu limite durante leitura")
    ctx.image_name = source.name if isinstance(source, Path) else (file_hint or "imagem")
    ctx.image_size = len(ctx.content_bytes)
    _hashing_data(ctx)
    ctx.target.source = source
    if problem := collect_image(ctx):
        return problem
    ctx.target.features = ctx.features
    ctx.target.structure = dict(ctx.metadata)
    rules = get_rules()
    if problem := execute_rules(ctx, rules, settings.get("max_rule_seconds", 12.0)):
        return problem
    meta_attribute(ctx)
    try:
        average = calculate_score(ctx, k, score_model,
                                  config.get("scoring", {}).get("caps", {}),
                                  config.get("scoring", {}).get("groups", {}))
    except ValueError as exc:
        if str(exc) == "no_rule_coverage":
            return error("no_rule_coverage", "Não há evidências avaliáveis suficientes")
        return error("invalid_scoring_configuration", str(exc))
    return build_response(ctx, len(rules), score_model, k, average)
