import asyncio
import logging
import sqlite3
from fastapi.responses import JSONResponse
from providers.database.quota import reserve_anonymous_count, refund_anonymous_count
from providers.database.usage import reserve_usage, refund_usage, PLAN_LIMITS

logger = logging.getLogger(__name__)

class ScanQuota:
    def __init__(self, user, ip, module):
        self.user = user
        self.ip = ip
        self.module = module
        self.date = None
        self.started = False
        self.completed = False
        self.settled = False

    def reserve(self):
        if self.date is not None or self.settled:
            raise RuntimeError("A reserva de cota já foi utilizada")
        if self.user is None:
            self.date = reserve_anonymous_count(self.ip)
            if self.date is None:
                return JSONResponse(status_code=401, content={
                    "error": "limite de scans anônimos atingido",
                    "detail": "Crie uma conta para continuar usando o ScamLens.",
                })
        else:
            self.date = reserve_usage(self.user["id"], self.module, self.user["plan_name"],
                                      is_admin=self.user.get("is_admin", False))
            if self.date is None:
                limit = PLAN_LIMITS.get(self.user["plan_name"])
                return JSONResponse(status_code=429, content={
                    "error": "limite diário atingido",
                    "detail": f"Seu plano {self.user['plan_label']} permite {limit} scans por dia.",
                })
        return None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        if self.settled or self.date is None:
            return False
        self.settled = True
        cancelled = exc_type is not None and issubclass(exc_type, asyncio.CancelledError)
        if self.completed or (self.started and cancelled):
            return False
        try:
            if self.user is None:
                refund_anonymous_count(self.ip, self.date)
            else:
                refund_usage(self.user["id"], self.module, self.date)
        except sqlite3.Error:
            logger.exception("Não foi possível devolver a reserva de cota do módulo %s", self.module)
        return False
