import sqlite3
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from fastapi import APIRouter, Request, Response, HTTPException
from jwt import PyJWTError, encode, decode
import bcrypt
from .schema.auth_schema import LoginBody, RegisterBody
from scamLens import config
from providers.database.users import get_user_by_email, create_user, get_user_by_id
from providers.database.tokens import revoke_token, is_token_revoked
from scamLens import get_settings

router = APIRouter(prefix="/api/auth", tags=["auth"])
settings = get_settings()

cookie_config = config["cookies"]
secure = cookie_config["secure"]
samesite = cookie_config["samesite"]
httponly = cookie_config["httponly"]
ttl_minutes = cookie_config["ttl_minutes"]
ttl_days = cookie_config["ttl_days"]

COOKIE_KWARGS = {"httponly": httponly, "secure": secure, "samesite": samesite}

SECRET_KEY = settings.jwt_secret
if not SECRET_KEY:
    raise RuntimeError("SERVER ERROR JWT_SECRET not defined in the environment")

ALGORITHM = "HS256"
ACCESS_TTL = timedelta(minutes=ttl_minutes)
REFRESH_TTL = timedelta(days=ttl_days)
_DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt()).decode()

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def _make_token(user_id: int, ttl: timedelta, token_type: str, remember: bool = False) -> str:
    expire = datetime.now(timezone.utc) + ttl
    payload = {
        "sub": str(user_id),
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": token_type,
        "jti": uuid4().hex,
        "remember": remember,
    }
    return encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def _set_cookies(response: Response, user_id: int, remember: bool) -> None:
    refresh_ttl = REFRESH_TTL if remember else timedelta(days=1)

    response.set_cookie(
        key="access_token",
        value=_make_token(user_id, ACCESS_TTL, "access"),
        max_age=int(ACCESS_TTL.total_seconds()),
        **COOKIE_KWARGS,
    )

    response.set_cookie(
        key="refresh_token",
        value=_make_token(user_id, refresh_ttl, "refresh", remember=remember),
        max_age=int(refresh_ttl.total_seconds()),
        **COOKIE_KWARGS,
    )

def decode_token(token: str, expected_type: str) -> dict:
    try:
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        if payload.get("type") != expected_type:
            raise HTTPException(status_code=401, detail="Token inválido")

        if expected_type == "refresh":
            jti = payload.get("jti")
            if jti and is_token_revoked(jti):
                raise HTTPException(status_code=401, detail="Token revogado")

        return payload

    except HTTPException:
        raise
    except (PyJWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

def _revoke_if_valid(token: str | None, expected_type: str) -> None:
    if not token:
        return
    
    try:
        payload = decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") == expected_type:
            jti = payload.get("jti")
            exp_raw = payload.get("exp")
            if jti and exp_raw is not None:
                exp = datetime.fromtimestamp(exp_raw, tz=timezone.utc)
                revoke_token(jti, expires_at=exp)
    except PyJWTError:
        pass

@router.post("/register", status_code=201)
def register(body: RegisterBody, response: Response):
    hashed = hash_password(body.password)
    try:
        user = create_user(email=body.email, name=body.name, hashed_password=hashed)
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="E-mail já cadastrado")

    _set_cookies(response, user["id"], remember=False)
    return {"id": user["id"], "email": user["email"], "name": user["name"]}

@router.post("/login")
def login(body: LoginBody, response: Response):
    user = get_user_by_email(body.email)
    stored_hash = user["password"] if user else _DUMMY_HASH
    valid = verify_password(body.password, stored_hash)

    if not user or not valid:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Conta desativada")

    _set_cookies(response, user["id"], body.remember)
    return {"ok": True}

@router.post("/logout")
def logout(request: Request, response: Response):
    _revoke_if_valid(request.cookies.get("access_token"), "access")
    _revoke_if_valid(request.cookies.get("refresh_token"), "refresh")
    response.delete_cookie("access_token", **COOKIE_KWARGS)
    response.delete_cookie("refresh_token", **COOKIE_KWARGS)
    return {"ok": True}

@router.post("/refresh")
def refresh(response: Response, request: Request):
    token = request.cookies.get("refresh_token")

    if not token:
        raise HTTPException(status_code=401, detail="Refresh token ausente")

    payload = decode_token(token, "refresh")
    user_id = int(payload["sub"])
    remember = payload.get("remember", False)

    user = get_user_by_id(user_id)
    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Usuário inativo")

    jti = payload.get("jti")
    if jti:
        exp = datetime.fromtimestamp(payload["exp"], tz=timezone.utc)
        revoke_token(jti, expires_at=exp)

    _set_cookies(response, user_id, remember=remember)
    return {"ok": True}