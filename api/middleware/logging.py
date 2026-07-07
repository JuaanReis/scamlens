from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from providers.database.connection import get_connection
from scamLens import config

LOGGED_PREFIXES = ("/api/scurl", "/api/qr")
_TRUST_PROXY = config.get("logging", {}).get("trust_proxy", False)

def _get_client_ip(request: Request) -> str:
    if _TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.client.host

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        if any(request.url.path.startswith(p) for p in LOGGED_PREFIXES):
            ip = _get_client_ip(request)
            user_id = getattr(request.state, "user_id", None)
            scan_id = getattr(request.state, "scan_id", None)

            conn = get_connection()
            conn.execute(
                """
                INSERT INTO request_logs (ip, endpoint, method, user_id, scan_id, status_code)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (ip, request.url.path, request.method, user_id, scan_id, response.status_code),
            )
            conn.commit()

        return response