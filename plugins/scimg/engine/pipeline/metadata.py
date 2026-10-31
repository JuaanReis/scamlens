from hashlib import sha256

def _hashing_data(ctx):
    ctx.image_hash = sha256(ctx.content_bytes).hexdigest()
