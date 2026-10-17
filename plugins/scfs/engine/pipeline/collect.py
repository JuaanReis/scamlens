import os
import stat
from hashlib import sha256
from pathlib import Path
from ...parsers.executable import parse
from ...parsers.common import extract_strings
from ...providers.reputation import collect
from ...parsers.features import prepare_features

def collect_target_data(ctx, source, settings, name=None, provider=None):
    if isinstance(source, bytes):
        data = source
        filename = name or "sample"
        if len(data) > settings.max_file_bytes:
            raise ValueError("file exceeds max_file_bytes")
    elif isinstance(source, (str, Path)):
        path = Path(source)
        flags = os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NONBLOCK', 0)
        fd = os.open(path, flags)

        with os.fdopen(fd, 'rb') as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise ValueError("source must be a regular file")
            
            if before.st_size > settings.max_file_bytes:
                raise ValueError("file exceeds max_file_bytes")
            
            data = handle.read(settings.max_file_bytes+1)
            after = os.fstat(handle.fileno())

            if len(data) > settings.max_file_bytes:
                raise ValueError("file exceeds max_file_bytes")
            
            if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                raise ValueError("file changed during collection; retry with a stable copy")
            
        filename = name or path.name
    else:
        raise TypeError("source must be str, Path or bytes")
    
    if not data:
        raise ValueError("empty file")
    target = ctx.target
    target.name, target.data = str(filename), data
    target.sha256 = sha256(data).hexdigest()
    target.structure = parse(data, target.name)
    target.strings, target.strings_truncated = extract_strings(data, settings.max_strings)
    prepare_features(target)

    if target.features.get("embedded_search_truncated"):
        ctx.warnings.append("embedded PE search limit reached; coverage reduced")

    ctx.warnings.extend(target.structure.get('warnings', []))
    if target.strings_truncated:
        ctx.warnings.append("string extraction limit reached; coverage reduced")

    try:
        target.reputation = collect(provider, target.sha256)
        
    except Exception as exc:
        ctx.warnings.append("reputation unavailable: " + type(exc).__name__)
