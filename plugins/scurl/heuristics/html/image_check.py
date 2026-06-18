from urllib.parse import urlparse
from plugins.scurl.models.result_base import ResultBase
from ..registry import register

@register(name="image_src_check", category="html", severity="low", weight=1.5, tags=["html", "image"])
def image_src_check(structure: dict) -> ResultBase:
    tree = structure.get("html_parser")
    if tree is None:
        return ResultBase(
            value=0,
            normalized=None,
            details={"error": "HTML não disponível"}
        )
 
    original_domain = structure.get("hostname", "")
    images = tree.css("img[src]")
    external_images = []
 
    for img in images:
        src = img.attributes.get("src", "")
        if not src:
            continue
        parsed = urlparse(src)
        if parsed.netloc and parsed.netloc != original_domain:
            external_images.append(src)
 
    total = len(images)
    external_count = len(external_images)
    ratio = external_count / total if total > 0 else 0.0
 
    return ResultBase(
        value=ratio,
        normalized=round(min(ratio, 1.0), 4) if ratio > 0 else None,
        details={
            "total_images": total,
            "external_image_count": external_count,
            "external_ratio": round(ratio, 4),
            "external_images": external_images
        }
    )