from re import compile
from uuid import uuid4
from pathlib import Path
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from api.middleware.auth import get_current_user
from providers.database.repository import get_user_activity
from providers.database.users import update_avatar
from scamLens import config

router = APIRouter(prefix="/api/user", tags=["users"])

AVATARS_DIR = Path(config.get("paths", {}).get("avatar", ""))
MAX_SIZE_BYTES = 2 * 1024 * 1024 

ALLOWED_SIGNATURES: list[tuple[bytes, str, str]] = [
    (b"\xff\xd8\xff", "jpg",  "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "png", "image/png"),
    (b"RIFF", "webp", "image/webp"),
    (b"GIF87a", "gif",  "image/gif"),
    (b"GIF89a", "gif",  "image/gif"),
]

_AVATAR_FILENAME_RE = compile(r"^\d+_[0-9a-f]{32}\.(jpg|png|webp|gif)$")

def _detect(data: bytes) -> tuple[str, str] | None:
    for magic, ext, mime in ALLOWED_SIGNATURES:
        if not data.startswith(magic):
            continue
        if ext == "webp" and data[8:12] != b"WEBP":
            continue
        return ext, mime
    return None

@router.get("/me")
def me(user: dict = Depends(get_current_user)):
    activity = get_user_activity(user["id"])
    return {
        "name": user["name"],
        "email": user["email"],
        "avatar_url": user["avatar_url"],
        "plan": {
            "name": user["plan_name"],
            "label": user["plan_label"],
            "price": user["plan_price"] / 100,
        },
        "activity": activity,
    }

@router.post("/avatar")
async def upload_avatar(file: UploadFile = File(...), user: dict = Depends(get_current_user)):
    contents = await file.read(MAX_SIZE_BYTES + 1)
    if len(contents) > MAX_SIZE_BYTES:
        raise HTTPException(status_code=413, detail="File too large. Maximum 2MB.")

    detected = _detect(contents)
    if detected is None:
        raise HTTPException(status_code=415, detail="Invalid format. Use JPEG, PNG, WebP, or GIF.")

    ext, _ = detected

    AVATARS_DIR.mkdir(parents=True, exist_ok=True)

    filename = f"{user['id']}_{uuid4().hex}.{ext}"
    path = AVATARS_DIR / filename

    old_url = user.get("avatar_url")
    if old_url:
        old_filename = old_url.split("/")[-1]
        if _AVATAR_FILENAME_RE.match(old_filename):
            old_path = AVATARS_DIR / old_filename
            if old_path.exists():
                old_path.unlink()

    path.write_bytes(contents)

    avatar_url = f"{AVATARS_DIR}/{filename}"
    update_avatar(user["id"], avatar_url)

    return {"avatar_url": avatar_url}