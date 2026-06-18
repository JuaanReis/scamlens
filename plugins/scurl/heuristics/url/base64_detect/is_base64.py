from base64 import b64decode, binascii
from re import fullmatch
from .regex import BASE64_RE, BASE64_URL_RE
from .clean_segment import clean_segment

def is_base64(segment: str) -> bool:
    segment = clean_segment(segment)

    if len(segment) < 12:
        return False

    padded = segment + "=" * (-len(segment) % 4)

    is_std = bool(BASE64_RE.fullmatch(padded))
    is_url = bool(BASE64_URL_RE.fullmatch(segment))

    if not is_std and not is_url:
        return False

    if "_" in segment:
        parts = segment.split("_")
        if any(p.isdigit() for p in parts):
            return False

    try:
        if is_url:
            decoded = b64decode(segment.replace("-", "+").replace("_", "/") + "==", validate=False)
        else:
            decoded = b64decode(padded, validate=True)

        if len(decoded) < 6:
            return False

        non_printable = sum(1 for b in decoded if b < 32 or b > 126)
        ratio_non_printable = non_printable / len(decoded)

        if ratio_non_printable > 0.3:
            return False
        
        if decoded.isascii():
            unique_ratio = len(set(decoded)) / len(decoded)
            if unique_ratio < 0.4:
                return False

        return True

    except (ValueError, binascii.Error):
        return False

def is_tracking_id(segment: str) -> bool:
    """
    Detecta IDs de tracking gerados automaticamente.
    Ex: mt-vs9xb5-1775007854-871439346
    """

    segment = segment.lower()
    
    parts = segment.split('-')
    if len(parts) < 3:
        return False

    has_long_number = any(p.isdigit() and len(p) >= 8 for p in parts)
    has_alnum = any(not p.isdigit() and p.isalnum() and len(p) >= 4 for p in parts)

    return has_long_number and has_alnum