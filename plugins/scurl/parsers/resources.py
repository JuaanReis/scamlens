from urllib.parse import urljoin, urlparse
from providers.domain.structure import same_owner


def page_url(structure: dict) -> str:
    return structure.get("url", "")


def base_url(structure: dict) -> str:
    tree = structure.get("html_parser")
    node = tree.css_first("base[href]") if tree else None
    if node is not None:
        return urljoin(page_url(structure), node.attributes.get("href", ""))
    return page_url(structure)


def destination(value: str, structure: dict):
    try:
        return urlparse(urljoin(base_url(structure), (value or "").strip()))
    except (ValueError, UnicodeError):
        return None


def external(value: str, structure: dict) -> bool:
    parsed = destination(value, structure)
    return bool(
        parsed
        and parsed.scheme in ("http", "https")
        and parsed.hostname
        and not same_owner(parsed.hostname, structure.get("hostname", ""))
    )


def has_password(tree) -> bool:
    return bool(
        tree
        and any(
            n.attributes.get("type", "").lower() == "password"
            for n in tree.css("input")
        )
    )
