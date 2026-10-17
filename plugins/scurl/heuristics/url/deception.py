import unicodedata
from urllib.parse import urlparse
from plugins.scurl.models.result_base import ResultBase
from providers.domain.structure import owner
from ..registry import register


@register(
    name="brand_subdomain",
    category="url",
    severity="high",
    weight=3.0,
    tags=["deception", "hostname"],
)
def brand_subdomain(structure):
    # Generic full-domain bait, not a popularity allowlist: bank.com.attacker.net.
    subs = structure.get("subdomain", [])
    from providers.domain.structure import extract

    bait = []
    for i in range(len(subs) - 1):
        candidate = ".".join(subs[i:])
        if extract(candidate).suffix and owner(candidate) != owner(
            structure.get("hostname", "")
        ):
            bait.append(candidate)
    return ResultBase(len(bait), 0.9 if bait else 0, dict(domain_bait=bait[:8]))


@register(
    name="unicode_mixed_script",
    category="url",
    severity="medium",
    weight=2.5,
    tags=["deception", "idn"],
)
def unicode_mixed_script(structure):
    host = structure.get("hostname", "")
    try:
        host = host.encode("ascii").decode("idna")
    except (UnicodeError, UnicodeEncodeError):
        pass
    from providers.domain.structure import extract

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
        int(mixed),
        0.8 if mixed else 0,
        dict(scripts=sorted(scripts), mixed_script=mixed),
    )


@register(
    name="cleartext_transport",
    category="url",
    severity="medium",
    weight=3.0,
    tags=["transport", "http"],
)
def cleartext_transport(structure):
    insecure = structure.get("scheme") == "http"
    # HTTP alone stays below the suspicious threshold; it can corroborate other signals.
    return ResultBase(
        int(insecure),
        0.55 if insecure else 0,
        {"cleartext_transport": insecure, "does_not_prove_phishing": True},
    )
