from urllib.parse import unquote

def clean_segment(segment: str) -> str:
    segment = unquote(segment)
    segment = segment.strip()
    segment = segment.replace(" ", "")
    segment = segment.replace("\n", "")
    segment = segment.replace("\r", "")
    return segment