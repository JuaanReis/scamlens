from math import ceil
from threading import Lock
from time import monotonic
from fastapi.routing import APIRoute
from fastapi.responses import JSONResponse
from scamLens import config

_windows = {}
_lock = Lock()
_cleanup_at = 0.0

class RateLimitedRoute(APIRoute):
    def get_route_handler(self):
        handler = super().get_route_handler()
        endpoint = f"{self.endpoint.__module__}.{self.endpoint.__qualname__}:{self.path}"

        async def limited_handler(request):
            global _cleanup_at
            options = config["rate_limit"]
            if options["enabled"]:
                now = monotonic()
                ip = request.client.host if request.client else "unknown"
                key = (ip, endpoint, request.method)
                with _lock:
                    if now >= _cleanup_at:
                        expired = [name for name, (end, _) in _windows.items() if end <= now]
                        for name in expired:
                            del _windows[name]
                        _cleanup_at = now + 60
                    end, count = _windows.get(key, (now + 60, 0))
                    if end <= now:
                        end, count = now + 60, 0
                    allowed = count < options["requests_per_minute"]
                    if allowed:
                        _windows[key] = (end, count + 1)
                if not allowed:
                    return JSONResponse(
                        status_code=429, content={"error": "limite de requisições por minuto atingido"},
                        headers={"Retry-After": str(max(1, ceil(end - now)))},
                    )
            return await handler(request)

        return limited_handler
