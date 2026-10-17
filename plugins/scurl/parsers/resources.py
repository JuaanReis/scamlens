from urllib.parse import urljoin, urlparse
from providers.domain.structure import same_owner


def page_url(structure):
    return structure.get("url", "")


def base_url(structure):
    tree = structure.get("html_parser")
    node = tree.css_first("base[href]") if tree else None
    return (
        urljoin(page_url(structure), (node.attributes["href"] or ""))
        if node
        else page_url(structure)
    )


def destination(value, structure):
    try:
        return urlparse(urljoin(base_url(structure), (value or "").strip()))
    except (ValueError, UnicodeError):
        return None


def external(value, structure):
    parsed = destination(value, structure)
    return bool(
        parsed
        and parsed.scheme in ("http", "https")
        and parsed.hostname
        and not same_owner(parsed.hostname, structure.get("hostname", ""))
    )


def has_password(tree):
    return bool(
        tree
        and any(
            n.attributes.get("type", "").lower() == "password"
            for n in tree.css("input")
        )
    )
