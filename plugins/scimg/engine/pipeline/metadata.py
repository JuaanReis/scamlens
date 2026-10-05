from plugins.scimg.models.scan_context import ScanContext
from hashlib import sha256

def atributte_data(ctx: ScanContext, data: dict) -> None:
    ctx.metadata = data

def _hashing_data(ctx: ScanContext, data: dict) -> None:
    ctx.hashes = sha256(ctx.image_name).hexdigest()