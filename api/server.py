from scamLens import __version__, config, get_settings
from time import perf_counter
START = perf_counter() # Start measuring time for server startup
import logging
from contextlib import asynccontextmanager
from sys import platform
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from api.middleware.limiter import limiter
from api.logs import LOGS_ENABLED, initialize_logging
from api.middleware.logging.logging import RequestLoggingMiddleware
from api.router.admin import router as admin_router
from api.router.auth import router as auth_router
from api.router.system import router as system_router
from api.router.users import router as users_router
from api.router.scurl.url import router as scurl_analyze_router
from api.router.scurl.qr import router as scurl_qr_router
from api.router.scurl.scans import router as scurl_scans_router
from providers.database.connection import get_connection, init_db
from providers.database.seed import ensure_admin_exists
from scamLens.paths import STATIC, _STORAGE
settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):

    if LOGS_ENABLED:
        initialize_logging(perf_counter() - START) # Initialize logging with the server startup time

    try:
        init_db()
    except Exception as e:
        if LOGS_ENABLED:
            logging.exception(
                f"Database initialization failed: {e}"
            )
        raise

    conn = get_connection()
    ensure_admin_exists(conn)

    startup_time = perf_counter() - START # Measure the time taken for server startup

    if LOGS_ENABLED:
        logging.info(
            "Server startup completed in %.3fs",
            startup_time,
        )

    yield

_docs_url = None if settings.environment == "production" else "/docs"
_openapi_url = None if settings.environment == "production" else "/openapi.json"
_redoc_url = None if settings.environment == "production" else "/redoc"

app = FastAPI(
    title="scamLens",
    version=__version__,
    docs_url=_docs_url,
    openapi_url=_openapi_url,
    redoc_url=_redoc_url,
    lifespan=lifespan,
)

app.mount("/static", StaticFiles(directory=STATIC), name="static")
app.mount("/storage", StaticFiles(directory=str(_STORAGE)), name="storage")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

if LOGS_ENABLED:
    app.add_middleware(RequestLoggingMiddleware)

cors_config = config["cors"]
if cors_config["enabled"]:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_config["allow_origins"],
        allow_credentials=cors_config["allow_credentials"],
        allow_methods=cors_config["allow_methods"],
        allow_headers=cors_config["allow_headers"],
        expose_headers=cors_config["expose_headers"],
        max_age=cors_config["max_age"],
    )

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(system_router)
app.include_router(admin_router)
app.include_router(scurl_analyze_router, prefix="/api/scurl")
app.include_router(scurl_scans_router, prefix="/api/scurl")
app.include_router(scurl_qr_router, prefix="/api/scurl/qr")

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    if LOGS_ENABLED:
        logging.exception("Unhandled server error")

    return JSONResponse(
        status_code=500,
        content={
            "error": "internal server error"
        },
    )

def run():
    server = config["server"]
    logs = config["logs"]["enabled"]
    workers = 1 if platform == "win32" else server["workers"]
    
    uvicorn.run(
        app="api.server:app",
        host=server["host"],
        port=server["port"],
        workers=workers,
        reload=server["reload"],
        access_log=not logs
    )

if __name__ == "__main__":
    run()