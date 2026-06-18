from re import compile

BASE64_RE = compile(r'^[A-Za-z0-9+/]+={0,2}$')
BASE64_URL_RE = compile(r'^[A-Za-z0-9_-]+={0,2}$')
TRACKING_ID_RE = compile(
    r'^[a-z]{2,6}-[a-z0-9]+-[\d]+-[\d]+$'  # padrão: prefix-hash-num-num
)