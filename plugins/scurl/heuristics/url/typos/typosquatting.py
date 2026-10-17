from functools import lru_cache
from pathlib import Path
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.datasets.wordlists.wordlist_loader import (
    domain_generator as load_domains,
)
from plugins.scurl.heuristics.url.typos.index import build_index
from plugins.scurl.heuristics.url.typos.detect import detect
from ...registry import register

_WORDLIST_PATH = (
    Path(__file__).resolve().parents[3] / "datasets" / "wordlists" / "brands.txt"
)


def _load_index() -> dict:
    try:
        domains = list(load_domains(str(_WORDLIST_PATH)))
        return build_index(domains)
    except Exception:
        return {}


_BY_LEN = _load_index()


@lru_cache(maxsize=2048)
def _detect_cached(domain):
    return detect(domain, _BY_LEN)


@register(
    name="typosquatting",
    category="url",
    severity="high",
    weight=3.5,
    tags=["url", "typosquatting", "phishing"],
)
def typosquatting(structure: dict) -> ResultBase:
    registered_domain = structure.get("registered_domain", "")
    if not registered_domain:
        return ResultBase(
            value=0, normalized=None, details={"error": "domínio não disponível"}
        )

    domain = registered_domain.split(".")[0]

    if not _BY_LEN:
        return ResultBase(
            value=0, normalized=None, details={"error": "wordlist não carregada"}
        )

    return _detect_cached(domain)
