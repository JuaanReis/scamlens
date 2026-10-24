import asyncio
from functools import partial

async def run_scan(quota, function, *args, **kwargs):
    future = asyncio.get_running_loop().run_in_executor(None, partial(function, *args, **kwargs))
    quota.started = True
    cancelled = False
    while not future.done():
        try:
            await asyncio.shield(future)
        except asyncio.CancelledError:
            cancelled = True
        except Exception:
            break
    if cancelled:
        if not future.cancelled():
            future.exception()
        raise asyncio.CancelledError
    return future.result()
