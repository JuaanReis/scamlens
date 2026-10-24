import os
from time import monotonic, sleep

if os.name == "nt":
    import msvcrt
else:
    import fcntl

def is_link(path):
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()

def acquire_lock(path, timeout=0):
    if is_link(path):
        raise OSError("Log lock must not be a link")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    handle = os.fdopen(os.open(path, flags, 0o600), "r+b", buffering=0)
    try:
        if os.fstat(handle.fileno()).st_size == 0:
            handle.write(b"\0")
        deadline = monotonic() + timeout
        while True:
            try:
                handle.seek(0)
                if os.name == "nt":
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                return handle
            except OSError:
                if monotonic() >= deadline:
                    raise
                sleep(min(0.02, max(0, deadline - monotonic())))
    except BaseException:
        handle.close()
        raise

def release_lock(handle):
    if handle is None:
        return
    try:
        handle.seek(0)
        if os.name == "nt":
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
    finally:
        handle.close()
