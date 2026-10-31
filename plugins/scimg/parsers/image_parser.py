"""Extração segura de metadados de imagens (parsers/ do scurl)."""
def safe_metadata(im):
    # Texto somente de metadados legíveis; não inspeciona aleatoriamente pixels comprimidos.
    records = []
    for k, v in list(im.info.items())[:128]:
        if k.lower() in ("icc_profile", "exif", "transparency", "dpi"):
            continue
        if isinstance(v, str):
            records.append(f"{k}: {v[:3000]}")
        elif isinstance(v, bytes) and k.lower() in ("xmp", "xml", "comment"):
            records.append(f"{k}: {v[:3000].decode('utf-8', 'replace')}")
    try:
        exif = im.getexif()
        for tag, v in list(exif.items())[:128]:
            if isinstance(v, str):
                records.append(f"exif_{tag}: {v[:3000]}")
    except (ValueError, TypeError, OSError):
        pass
    return "\n".join(records)[:65536]

