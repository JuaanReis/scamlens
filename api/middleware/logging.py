from time import perf_counter
from logging import getLogger
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from re import search, I
from providers.database.connection import get_connection
from scamLens import config

logger = getLogger("api.request")

LOGGED_PREFIXES = (
    "/api/scurl",
    "/api/qr",
)

_TRUST_PROXY = config.get("logging", {}).get("trust_proxy", False)

def _get_client_ip(request: Request) -> str:
    if _TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()

    return request.client.host if request.client else "-"

def _get_user_agent(request: Request) -> str:
    ua = request.headers.get("User-Agent", "-")

    if ua == "-":
        return "-"

    match = search(
        r"(Edg|OPR|Chrome|Firefox|Safari)/([\d.]+)",
        ua,
    )

    if match:
        browser, version = match.groups()

        if browser == "Safari" and "Chrome" in ua:
            return "Chrome/" + search(
                r"Chrome/([\d.]+)",
                ua,
            ).group(1).split(".")[0]

        return f"{browser}/{version.split('.')[0]}"

    match = search(r"curl/([\d.]+)", ua, I)

    if match:
        return f"curl/{match.group(1)}"

    return ua.split()[0][:30]

def _get_referer(request: Request) -> str:
    return request.headers.get("Referer", "-")

class RequestLoggingMiddleware(BaseHTTPMiddleware):

    async def dispatch(self, request: Request, call_next):

        start = perf_counter()

        response = await call_next(request)

        duration_ms = (perf_counter() - start) * 1000

        if any(
            request.url.path.startswith(prefix)
            for prefix in LOGGED_PREFIXES
        ):
            ip = _get_client_ip(request)

            user_id = getattr(
                request.state,
                "user_id",
                None
            )

            scan_id = getattr(
                request.state,
                "scan_id",
                None
            )

            conn = get_connection()

            try:
                conn.execute(
                    """
                    INSERT INTO request_logs (
                        ip,
                        endpoint,
                        method,
                        user_id,
                        scan_id,
                        status_code,
                        duration_ms
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        ip,
                        request.url.path,
                        request.method,
                        user_id,
                        scan_id,
                        response.status_code,
                        duration_ms,
                    ),
                )

                conn.commit()

            finally:
                conn.close()

        return response


class RequestTimerMiddleware(BaseHTTPMiddleware):

    async def dispatch(
        self,
        request: Request,
        call_next,
    ):
        start = perf_counter()

        response = await call_next(request)

        duration_ms = (
            perf_counter() - start
        ) * 1000

        request.state.elapsed = duration_ms

        ip = _get_client_ip(request)

        user_id = getattr(
            request.state,
            "user_id",
            None,
        )

        scan_id = getattr(
            request.state,
            "scan_id",
            None,
        )

        logger.info(
            "%d %s %s%s · %.2fms · ip=%s · user=%s · ua=%r · ref=%r",
            response.status_code,
            request.method,
            request.url.path,
            f"?{request.url.query}" if request.url.query else "",
            duration_ms,
            ip,
            user_id if user_id is not None else "-",
            _get_user_agent(request),
            _get_referer(request),
    )

        return response