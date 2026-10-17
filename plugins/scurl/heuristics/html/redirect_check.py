import re
from urllib.parse import urljoin
from plugins.scurl.models.result_base import ResultBase
from plugins.scurl.parsers.resources import external
from ..registry import register

ASSIGN = re.compile(r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]", re.I)
CALL = re.compile(
    r"(?:window\.)?location\.(?:replace|assign)\s*\(\s*['\"]([^'\"]+)['\"]", re.I
)


@register(
    name="redirect_check",
    category="html",
    severity="low",
    weight=1.0,
    tags=["html", "redirect"],
)
def redirect_check(structure):
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(0, None, {"error": "HTML não disponível"})
    redirects = []
    for node in tree.css("meta[http-equiv]"):
        if node.attributes.get("http-equiv", "").lower() != "refresh":
            continue
        match = re.search(r"url\s*=\s*(.+)", node.attributes.get("content", ""), re.I)
        if match:
            target = match.group(1).strip().strip("'\"")
            if external(target, structure):
                redirects.append(dict(type="meta_refresh", target=target))
    for script in tree.css("script:not([src])"):
        text = script.text() or ""
        for pattern in (ASSIGN, CALL):
            for match in pattern.finditer(text):
                if external(match.group(1), structure):
                    redirects.append(dict(type="js_redirect", target=match.group(1)))
    return ResultBase(
        len(redirects),
        0.3 if redirects else 0,
        dict(
            has_external_redirect=bool(redirects),
            redirect_count=len(redirects),
            redirects=redirects[:12],
        ),
    )
