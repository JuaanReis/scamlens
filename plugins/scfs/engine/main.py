from pathlib import Path
from typing import Optional
from ..models.scan_context import ScanContext
from ..config import Settings
from ..heuristics import get_rules
from ..parsers.common import ParseError
from .pipeline import (
    collect_target_data, execute_rules, calculate_score,
    build_response, build_error_response
)

def run_engine(source: Path | bytes | str, file_hint: Optional[str] = None, *, name: str | None = None, settings: Settings | None = None, reputation_provider=None) -> tuple[dict, dict]:
    """Analisa os bytes do arquivo sem executar seu conteúdo."""
    if settings is None:
        settings = Settings()
    rules = get_rules()
    unknown = set(settings.disabled_rules) - {rule.name for rule in rules}
    if unknown:
        raise ValueError(f"Regras desconhecidas: {sorted(unknown)}")

    ctx = ScanContext(source=source, file_hint=file_hint)
    try:
        collect_target_data(ctx, source, settings, name=name or file_hint, provider=reputation_provider)
    except ParseError as error:
        code = "unsupported_format" if str(error).startswith("unsupported format") else "invalid_file"
        return build_error_response(ctx, code, str(error))
    except (OSError, TypeError, ValueError) as error:
        return build_error_response(ctx, "invalid_source", str(error))

    execute_rules(ctx, rules, settings.disabled_rules)
    calculate_score(ctx, settings.k, settings.score_model)
    return build_response(ctx, settings.k)
