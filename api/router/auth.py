from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Response, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from jose import jwt, JWTError
import bcrypt
from providers.database.users import get_user_by_email, create_user
from os import getenv
from dotenv import load_dotenv
load_dotenv()

router = APIRouter(prefix="/api/auth", tags=["auth"])

SECRET_KEY = getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TTL = timedelta(minutes=30)
REFRESH_TTL = timedelta(days=30)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

class RegisterBody(BaseModel):
    email: EmailStr
    name: str
    password: str

class LoginBody(BaseModel):
    email: EmailStr
    password: str
    remember: bool = False

def _make_token(user_id: int, ttl: timedelta) -> str:
    expire = datetime.now(timezone.utc) + ttl
    return jwt.encode({"sub": str(user_id), "exp": expire}, SECRET_KEY, algorithm=ALGORITHM)

def _set_cookies(response: Response, user_id: int, remember: bool) -> None:
    refresh_ttl = REFRESH_TTL if remember else timedelta(days=1)

    response.set_cookie(
        key="access_token",
        value=_make_token(user_id, ACCESS_TTL),
        httponly=True,
        secure=False,          
        samesite="lax",       
        max_age=int(ACCESS_TTL.total_seconds())
    )

    response.set_cookie(
        key="refresh_token",
        value=_make_token(user_id, refresh_ttl),
        httponly=True,
        secure=False,        
        samesite="lax",
        max_age=int(refresh_ttl.total_seconds())
    )

def decode_token(token: str) -> int:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Token inválido ou expirado")

@router.post("/register", status_code=201)
def register(body: RegisterBody, response: Response):
    if get_user_by_email(body.email):
        raise HTTPException(status_code=409, detail="E-mail já cadastrado")

    hashed = hash_password(body.password)
    user = create_user(email=body.email, name=body.name, hashed_password=hashed)

    _set_cookies(response, user["id"], remember=False)
    return {"id": user["id"], "email": user["email"], "name": user["name"]}

@router.post("/login")
def login(body: LoginBody, response: Response):
    user = get_user_by_email(body.email)

    if not user or not user["password"]:
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    if not user or not user["password"] or not verify_password(body.password, user["password"]):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    if not user["is_active"]:
        raise HTTPException(status_code=403, detail="Conta desativada")

    _set_cookies(response, user["id"], body.remember)
    return {"ok": True}

@router.post("/logout")
def logout(response: Response):
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")
    return {"ok": True}

@router.post("/refresh")
def refresh(response: Response, request_cookies: dict = Depends(lambda req: req.cookies)):
    token = request_cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="Refresh token ausente")

    user_id = decode_token(token)
    _set_cookies(response, user_id, remember=True)
    return {"ok": True}