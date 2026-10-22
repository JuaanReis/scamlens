from pathlib import Path
from ..config import Settings
from ..models.scan_context import ScanContext
from ..parsers.common import ParseError
from ..heuristics import get_rules
from ..heuristics.common import key_kind
from .pipeline import (collect_target_data, execute_rules, calculate_score,
                       build_response, build_error_response)


def run_engine(source: str | bytes | Path, *, name: str | None = None,
               settings: Settings | None = None,
               expected: dict[str, str] | None = None) -> tuple[dict, dict]:
    """Analisa BR Code (Pix copia e cola) localmente. Não inicia transações nem URLs.

    Para ler arquivo, envie `Path`, não um caminho em string. `expected` é opcional:
    merchant_name, key, amount, txid, location_host.
    """
    settings = settings or Settings()
    rules = get_rules()
    unknown = set(settings.disabled_rules) - {rule.name for rule in rules}
    if unknown:
        raise ValueError("Regras desconhecidas: " + ", ".join(sorted(unknown)))
    ctx = ScanContext()
    try:
        collect_target_data(ctx, source, settings, name=name, expected=expected)
    except ParseError as error:
        return build_error_response(ctx, error.code, str(error))
    except (ValueError, TypeError, UnicodeError, OSError) as error:
        return build_error_response(ctx, "invalid_source", str(error))

    ctx.target.features["key_kind"] = key_kind(ctx.target.structure["key"])
    if ctx.target.structure["dynamic"] or ctx.target.structure["recurring"]:
        ctx.warnings.append("Location dinâmica/recorrente não consultada; recebedor, autorização do PSP e cobrança não foram verificados.")
    execute_rules(ctx, rules, settings.disabled_rules)
    if any(r["status"] == "ok" for r in ctx.heuristics):
        calculate_score(ctx, settings.k)
    return build_response(ctx, settings)
