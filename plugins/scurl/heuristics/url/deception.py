import unicodedata
from plugins.scurl.models.result_base import ResultBase
from providers.domain.structure import owner, extract
from ..registry import register


@register(name="brand_subdomain", category="url", severity="high", weight=3.0, tags=["deception", "hostname"])
def brand_subdomain(structure: dict, normalized: float = 0.9, max_findings: int = 8) -> ResultBase:
    """Identifica um domínio completo usado como isca em outro domínio."""
    subs = structure.get("subdomain", [])

    bait = []
    for i in range(len(subs) - 1):
        candidate = ".".join(subs[i:])
        if extract(candidate).suffix and owner(candidate) != owner(
            structure.get("hostname", "")
        ):
            bait.append(candidate)
    return ResultBase(
        value=len(bait),
        normalized=normalized if bait else 0,
        details={"domain_bait": bait[:max_findings]}
    )


@register(name="unicode_mixed_script", category="url", severity="medium", weight=2.5, tags=["deception", "idn"])
def unicode_mixed_script(structure: dict, normalized: float = 0.8) -> ResultBase:
    """Detecta a mistura de alfabetos no rótulo principal do domínio."""
    host = structure.get("hostname", "")
    try:
        host = host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeEncodeError):
        pass

    label = extract(host).domain
    scripts = {}
    for char in label:
        if not char.isalpha():
            continue
        name = unicodedata.name(char, "")
        for script in ("LATIN", "CYRILLIC", "GREEK"):
            if script in name:
                scripts[script] = True
    mixed = "LATIN" in scripts and ("CYRILLIC" in scripts or "GREEK" in scripts)
    return ResultBase(
        value=int(mixed),
        normalized=normalized if mixed else 0,
        details={"scripts": sorted(scripts), "mixed_script": mixed},
    )


@register(name="cleartext_transport", category="url", severity="medium", weight=3.0, tags=["transport", "http"])
def cleartext_transport(structure: dict, normalized: float = 0.55) -> ResultBase:
    """Registra transporte HTTP como um indício complementar."""
    insecure = structure.get("scheme") == "http"
    return ResultBase(
        value=int(insecure),
        normalized=normalized if insecure else 0,
        details={"cleartext_transport": insecure, "does_not_prove_phishing": True},
    )
