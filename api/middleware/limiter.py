from slowapi import Limiter
from slowapi.util import get_remote_address
from scamLens import config

rate_config = config["rate_limit"]
limits = []

if rate_config["enabled"]:
    rpm = rate_config["requests_per_minute"]
    limits.append(f"{rpm}/minute")

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=limits,
)