from fastapi import Request, HTTPException
from api.router.auth import decode_token
from providers.database.users import get_user_by_id

def _extract_token(request: Request) -> str | None:
    if token := request.cookies.get("access_token"):
        return token
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header[7:]
    return None

def get_current_user(request: Request) -> dict:
    token = _extract_token(request)

    if not token:
        raise HTTPException(status_code=401, detail="Não autenticado")

    payload = decode_token(token, "access")
    user_id = int(payload["sub"])
    user = get_user_by_id(user_id)

    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Usuário inválido")

    request.state.user_id = user["id"]
    request.state.token_expires_at = payload["exp"]
    return user

def get_current_admin(request: Request) -> dict:
    user = get_current_user(request)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Acesso negado")
    return user
