from logging import getLogger
from time import perf_counter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from .client import get_client_ip, get_referer, get_user_agent
from .database import log_request

logger = getLogger("api.request")

LOGGED_PREFIXES = (
    "/api/scurl",
    "/api/qr",
)

class RequestLoggingMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):
        start = perf_counter()

        response = await call_next(request)

        duration_ms = (perf_counter() - start) * 1000
        request.state.elapsed = duration_ms

        ip = get_client_ip(request)
        user_id = getattr(request.state, "user_id", None)
        scan_id = getattr(request.state, "scan_id", None)

        logger.info(
            "%d %s %s%s %.2fms %s %s %r %r",
            response.status_code,
            request.method,
            request.url.path,
            f"?{request.url.query}" if request.url.query else "",
            duration_ms,
            ip,
            user_id if user_id is not None else "-",
            get_user_agent(request),
            get_referer(request),
        )

        if any(request.url.path.startswith(prefix) for prefix in LOGGED_PREFIXES):
            log_request(
                ip=ip,
                endpoint=request.url.path,
                method=request.method,
                user_id=user_id,
                scan_id=scan_id,
                status_code=response.status_code,
                duration_ms=duration_ms,
            )

        return response