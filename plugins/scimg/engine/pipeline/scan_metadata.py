"""Atributos de rastreabilidade do scan, como em scurl."""
from uuid import uuid4
from datetime import datetime, timezone

def meta_attribute(ctx, processors=1):
    ctx.scan_id = uuid4().hex
    ctx.timestamp = datetime.now(timezone.utc)
    ctx.meta.scan_id = ctx.scan_id
    ctx.meta.timestamp = ctx.timestamp
    ctx.meta.image_hash = ctx.image_hash
    ctx.meta.threads = processors
