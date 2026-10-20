"""Cached bounded features; no network, subprocesses, imports or evaluation of targets."""
import re

def prepare_features(target):
    text = target.structure.get("text")
    if text is None:
        text = "\n".join(target.strings + target.structure.get("imports", []))
    else:
        # Only standalone comment lines; inline syntax/strings are not interpreted.
        # This is a conservative lexical filter, not an AST/data-flow analysis.
        suffix = target.name.lower().rsplit(".", 1)[-1]
        prefixes = ("#",) if suffix in ("ps1", "py", "sh") or text.startswith("#!") else ("rem ", "::") if suffix in ("bat", "cmd") else ("//",) if suffix == "js" else ("'",) if suffix == "vbs" else ()
        text = "\n".join(line for line in text.splitlines() if not any(line.lstrip().lower().startswith(p) for p in prefixes))
    target.evidence_text = text.casefold()
    # Find embedded PE headers, excluding offset zero. Validate signature and
    # COFF/optional-header footprint; do not recursively parse or execute them.
    data = target.data
    embedded = []
    cursor = attempts = 0
    while attempts < 64:
        offset = data.find(b"MZ", cursor)
        if offset < 0:
            break
        cursor, attempts = offset + 2, attempts + 1
        if offset == 0 or offset + 64 > len(data):
            continue
        pe = offset + int.from_bytes(data[offset+60:offset+64], "little")
        if not offset+64 <= pe <= len(data)-26 or data[pe:pe+4] != b"PE\0\0":
            continue
        count = int.from_bytes(data[pe+6:pe+8], "little")
        opt_size = int.from_bytes(data[pe+20:pe+22], "little")
        magic = int.from_bytes(data[pe+24:pe+26], "little")
        minimum = 112 if magic == 0x20b else 96
        if magic in (0x10b, 0x20b) and 1 <= count <= 96 and minimum <= opt_size and pe+24+opt_size+count*40 <= len(data):
            embedded.append(offset)
    target.features["embedded_pe_offsets"] = embedded[:12]
    target.features["embedded_search_truncated"] = attempts == 64 and data.find(b"MZ", cursor) >= 0
