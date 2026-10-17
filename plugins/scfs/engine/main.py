from pathlib import Path
from ..config import Settings
from ..models.scan_context import ScanContext
from ..heuristics import get_rules
from ..parsers.common import ParseError
from .pipeline.collect import collect_target_data
from .pipeline.execute import execute_rules
from .pipeline.score import calculate_score
from .pipeline.response_builder import build_response, build_error_response

def run_engine(source: str | Path | bytes, k: float | None = None, *,
               settings: Settings | None = None, name: str | None = None,
               reputation_provider=None) -> tuple[dict, dict]:
    from dataclasses import replace
    settings = settings or Settings()
    if k is not None:
        settings = replace(settings, k=k)
    rules = get_rules()
    unknown = set(settings.disabled_rules) - {r.name for r in rules}
    if unknown:
        raise ValueError("unknown disabled rules: " + ", ".join(sorted(unknown)))
    ctx = ScanContext()
    try:
        collect_target_data(ctx, source, settings, name, reputation_provider)
    except ParseError as exc:
        return build_error_response(ctx, "invalid_or_unsupported_executable", str(exc))
    except (OSError, ValueError, TypeError) as exc:
        return build_error_response(ctx, "invalid_source", str(exc))
    execute_rules(ctx, rules, settings.disabled_rules)
    calculate_score(ctx, settings.k, settings.score_model)
    return build_response(ctx, settings.k)
