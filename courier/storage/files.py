"""Small, careful file helpers shared by the keystore, the CA and the client."""
from __future__ import annotations

import os
from pathlib import Path


def atomic_write(path: Path, data: bytes, *, mode: int, overwrite: bool = False) -> None:
    """Write `data` to `path` so readers never see a partial file.

    The data goes to a temporary file created with `mode` from the start (never
    briefly wider), is flushed to disk, and is then renamed over `path` in one
    step. O_EXCL makes creation fail rather than follow a planted file or symlink.
    """
    path = Path(path)
    if path.exists() and not overwrite:
        raise FileExistsError(f"refusing to overwrite existing file {path}")

    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)  # os.open's mode is filtered by umask; set it exactly
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
