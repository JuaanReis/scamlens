import asyncio
from scamLens import config

scan_semaphore = asyncio.Semaphore(config["rate_limit"]["max_concurrent_scans"])
