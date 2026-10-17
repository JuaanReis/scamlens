from typing import Protocol

class ReputationProvider(Protocol):
    def lookup(self, sha256: str) -> dict | None:
        """Return {malicious: int, total: int, source: str}, or None if unknown.

        Implement requests/timeouts/retries in the host's providers package.
        The scanner calls this once with a SHA-256 only, never sample bytes.
        """
        ...

def collect(provider, digest):
    if provider is None:
        return None
    
    value = provider.lookup(digest)

    if value is None:
        return None
    
    if not isinstance(value, dict):
        raise ValueError("reputation must return a dict or None")
    
    malicious, total = value.get("malicious"), value.get("total")

    if (type(malicious) is not int or type(total) is not int or
            not 0 <= malicious <= total or total <= 0):
        raise ValueError("invalid reputation counts")
    
    source = value.get("source")
    if not isinstance(source, str) or not source:
        raise ValueError("reputation source is required")
    
    return dict(malicious=malicious, total=total, source=source[:200])
                    