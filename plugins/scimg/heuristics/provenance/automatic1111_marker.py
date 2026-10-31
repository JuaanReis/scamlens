"""Heurística de procedência declarada: automatic1111_marker."""
from plugins.scimg.models.result_base import ResultBase
from ..registry import register

MARKERS = ('automatic1111', 'a1111')

@register(name='automatic1111_marker', category="provenance", severity="high", weight=12.0,
          tags=["image", "metadata", "generator"], group="provenance")
def automatic1111_marker(data: dict) -> ResultBase:
    raw = data.get("metadata_text", "")
    if not raw:
        return ResultBase(value=0, normalized=None, details={"reason": "metadata_absent"})
    found = [marker for marker in MARKERS if marker in raw]
    return ResultBase(value=len(found), normalized=0.95 if found else None,
                      details={"markers": found, "warning": "Metadados podem ser forjados"})
