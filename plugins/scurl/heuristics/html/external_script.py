import re
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.html_parser import HTMLParser
from plugins.scurl.parsers.normalize_domain import normalize_domain
from plugins.scurl.parsers.resources import external, destination
from plugins.scurl import config
from ..registry import register

resource_config = config["resources"]
TRUSTED_DOMAINS = set(resource_config["trusted_domains"])
RESOURCE_CATEGORY = resource_config["categories"]

HARVEST_PATTERNS = [
    re.compile(r'fetch\s*\('),
    re.compile(r'XMLHttpRequest'),
    re.compile(r'\.open\s*\(\s*["\']POST'),
    re.compile(r'form\.submit\s*\('),
    re.compile(r'addEventListener\s*\(\s*["\']submit'),
    re.compile(r'FormData\s*\('),
]


def _matches(domain: str, expected: str) -> bool:
    return domain == expected or domain.endswith("." + expected)


def _categorize(domain: str) -> str:
    for category, domains in RESOURCE_CATEGORY.items():
        if any(_matches(domain, item) for item in domains):
            return category
    return "unknown"


def _detect_harvest(tree: HTMLParser, external_domains: set[str]) -> list[str]:
    findings = []
    for script in tree.css("script:not([src])"):
        text = script.text() or ""
        has_harvest = any(p.search(text) for p in HARVEST_PATTERNS)
        if not has_harvest:
            continue
        for domain in external_domains:
            if normalize_domain(domain) in text:
                findings.append(domain)
    return findings


@register(name="external_script", category="html", severity="medium", weight=3.0, tags=["html", "external", "script"])
def external_script(structure: dict) -> ResultBase:
    """Avalia scripts externos usando os dados já coletados, sem consultas de rede."""
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(value=0, normalized=None, details={"error": "HTML não disponível"})

    external_scripts = []
    suspicious_scripts = []
    domain_categories = {}
    external_domains = set()

    for script in tree.css("script[src]"):
        src = script.attributes.get("src", "")
        if not external(src, structure):
            continue
        parsed = destination(src, structure)
        domain = normalize_domain(parsed.hostname)
        external_scripts.append(src)
        external_domains.add(domain)
        domain_categories[domain] = _categorize(domain)
        if not any(_matches(domain, item) for item in TRUSTED_DOMAINS):
            suspicious_scripts.append(src)

    harvest_domains = _detect_harvest(tree, external_domains)
    if harvest_domains:
        score = 1.0
    elif suspicious_scripts:
        ratio = len(suspicious_scripts) / len(external_scripts)
        score = 0.5 + 0.5 * ratio
    else:
        score = 0.0

    return ResultBase(
        value=score,
        normalized=score if score > 0 else None,
        details={
            "has_suspicious_external_script": bool(suspicious_scripts),
            "external_script_count": len(external_scripts),
            "suspicious_script_count": len(suspicious_scripts),
            "unique_external_domains": len(external_domains),
            "domain_categories": domain_categories,
            "suspicious_scripts": suspicious_scripts,
            "harvest_detected": bool(harvest_domains),
            "harvest_domains": harvest_domains,
        }
    )
