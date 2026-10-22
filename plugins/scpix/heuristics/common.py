"""Utilitários estritamente locais, sem consultas a cadastros financeiros."""
import ipaddress
import re
import unicodedata
from decimal import Decimal


KEY_EMAIL = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@.]{2,}$")
KEY_PHONE = re.compile(r"^\+55\d{10,11}$")
KEY_EVP = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
KEY_CNPJ_ALPHA = re.compile(r"^[0-9A-Z]{12}[0-9]{2}$")
TXID = re.compile(r"^(\*\*\*|[A-Za-z0-9]{1,25})$")
AMOUNT = re.compile(r"^(?:0|[1-9]\d{0,9})(?:\.\d{1,2})?$")
HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
DANGEROUS_UNICODE = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}


def finding(active: bool, message: str, evidence=(), severity: float = 1.0):
    return (severity if active else 0.0), message, list(evidence) if active else []


def identity_norm(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def key_kind(key: str | None) -> str:
    if not key:
        return "unknown"
    if KEY_EVP.fullmatch(key):
        return "evp"
    if KEY_EMAIL.fullmatch(key):
        return "email"
    if KEY_PHONE.fullmatch(key):
        return "phone"
    if key.isascii() and key.isdigit() and len(key) == 11:
        return "cpf"
    if len(key) == 14 and KEY_CNPJ_ALPHA.fullmatch(key):
        return "cnpj"
    return "invalid"


def _digit_valid(value: str, width: int) -> bool:
    if len(value) != width or not value.isdigit() or len(set(value)) == 1:
        return False
    if width == 11:
        digit1 = (sum(int(d) * w for d, w in zip(value[:9], range(10, 1, -1))) * 10) % 11
        digit1 = 0 if digit1 == 10 else digit1
        digit2 = (sum(int(d) * w for d, w in zip(value[:10], range(11, 1, -1))) * 10) % 11
        digit2 = 0 if digit2 == 10 else digit2
        return value[-2:] == f"{digit1}{digit2}"
    digits = list(map(int, value))
    for index, weights in [(12, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]),
                           (13, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2])]:
        total = sum(d * w for d, w in zip(digits[:index], weights))
        calculated = 0 if total % 11 < 2 else 11 - total % 11
        if calculated != digits[index]:
            return False
    return True


def key_checksum_valid(key: str) -> bool | None:
    kind = key_kind(key)
    if kind == "cpf":
        return _digit_valid(key, 11)
    if kind == "cnpj" and key.isdigit():
        return _digit_valid(key, 14)
    return None


def location_flags(value: dict) -> dict:
    host = value.get("host")
    if not host:
        return {"invalid_host": True, "private": False, "ip": False, "idn": False}
    ip = None
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    labels = host.rstrip(".").split(".")
    valid_dns = len(host) <= 253 and len(labels) >= 2 and all(HOST_LABEL.fullmatch(l) for l in labels)
    private = bool(ip and not ip.is_global) or host in ("localhost", "localhost.localdomain") or host.endswith((".local", ".internal", ".test", ".invalid"))
    return {"invalid_host": not valid_dns and ip is None, "private": private,
            "ip": ip is not None, "idn": any(label.startswith("xn--") for label in labels)}


def safely_format_decimal(amount: Decimal | None) -> str | None:
    return format(amount, "f") if amount is not None and amount.is_finite() else None
