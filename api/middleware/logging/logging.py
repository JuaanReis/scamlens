import logging
from time import perf_counter
from starlette.requests import Request
from scamLens import config
from .client import get_client_ip, get_referer, get_user_agent
from .database import log_request

logger = logging.getLogger("api.request")

def matches_prefix(path, prefixes):
    return any(prefix == "/" or path == prefix.rstrip("/")
               or path.startswith(prefix.rstrip("/") + "/") for prefix in prefixes)

class RequestLoggingMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        start = perf_counter()
        status = 500

        async def logged_send(message):
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, logged_send)
        finally:
            duration_ms = (perf_counter() - start) * 1000
            request = Request(scope)
            request.state.elapsed = duration_ms
            options = config["logs"]["requests"]
            database = config["logs"]["database"]
            path = request.url.path
            ip = get_client_ip(request)
            user_id = getattr(request.state, "user_id", None)
            scan_id = getattr(request.state, "scan_id", None)
            level = logging.ERROR if status >= 500 else logging.WARNING if status >= 400 else logging.INFO

            if (options["enabled"] and logger.isEnabledFor(level)
                    and matches_prefix(path, options["include_prefixes"])
                    and not matches_prefix(path, options["exclude_prefixes"])):
                target = path
                if options["include_query"] and request.url.query:
                    target += "?" + request.url.query
                details = ""
                if options["include_user_agent"]:
                    details += f" user_agent={get_user_agent(request)!r}"
                if options["include_referer"]:
                    details += f" referer={get_referer(request)!r}"
                logger.log(level, "%d %s %s %.2fms ip=%s user=%s%s",
                           status, request.method, target, duration_ms, ip,
                           user_id if user_id is not None else "-", details)

            if database["enabled"] and matches_prefix(path, database["include_prefixes"]):
                log_request(ip=ip, endpoint=path, method=request.method,
                            user_id=user_id, scan_id=scan_id, status_code=status,
                            duration_ms=duration_ms, module=_request_module(path))

def _request_module(path: str) -> str | None:
    if matches_prefix(path, ("/api/scurl/qr", "/api/qr")):
        return "scqr"
    for module in ("scurl", "scfs", "scpix", "chat"):
        if matches_prefix(path, (f"/api/{module}",)):
            return module
    return None
