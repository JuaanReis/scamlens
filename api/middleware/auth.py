from fastapi import Request, HTTPException
from api.router.auth import decode_token
from providers.database.users import get_user_by_id

def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Não autenticado")

    user_id = decode_token(token)
    user = get_user_by_id(user_id)

    if not user or not user["is_active"]:
        raise HTTPException(status_code=401, detail="Usuário inválido")

    request.state.user_id = user["id"]
    return user

def get_current_admin(request: Request) -> dict:
    user = get_current_user(request)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Acesso negado")
    return user