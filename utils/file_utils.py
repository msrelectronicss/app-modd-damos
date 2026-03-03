# =============================================================================
# BinModder - File Utilities
# =============================================================================
# Safe file operations: atomic writes, backups, directory creation, and
# metadata inspection for binary files.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

import os
import shutil
import tempfile
import hashlib
import time
from pathlib import Path
from typing import Dict, Any, Optional


# =============================================================================
# Backup
# =============================================================================

def backup_file(path: "str | Path", suffix: str = ".bak") -> Path:
    """Create a timestamped backup copy of *path* in the same directory.

    Returns the path of the created backup file.

    Parameters
    ----------
    path : str | Path
        File to back up. Must exist.
    suffix : str
        Extension appended to the backup name (default ``.bak``).
        A timestamp is always inserted before the suffix so multiple
        backups of the same file never overwrite each other.

    Raises
    ------
    FileNotFoundError
        If *path* does not exist.
    """
    src = Path(path)
    if not src.exists():
        raise FileNotFoundError(f"Cannot back up '{src}': file not found")

    ts = time.strftime("%Y%m%d_%H%M%S")
    dst = src.with_name(f"{src.stem}.{ts}{suffix}")
    shutil.copy2(src, dst)
    return dst


# =============================================================================
# Atomic write
# =============================================================================

def atomic_write(path: "str | Path", data: bytes) -> None:
    """Write *data* to *path* atomically using a temp file + rename.

    Prevents partial writes that would corrupt the destination file if the
    process is interrupted mid-write.

    Parameters
    ----------
    path : str | Path
        Destination file path. Parent directory must exist.
    data : bytes
        Raw bytes to write.
    """
    dst = Path(path)
    dir_ = dst.parent
    fd, tmp = tempfile.mkstemp(dir=dir_, prefix=".bm_tmp_")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, dst)          # atomic on POSIX; best-effort on Windows
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def safe_write(path: "str | Path", data: bytes, backup: bool = False) -> None:
    """Write *data* to *path*, optionally creating a backup first.

    Parameters
    ----------
    path : str | Path
        Destination file.
    data : bytes
        Bytes to write.
    backup : bool
        If ``True`` and the destination already exists, a ``.bak`` copy is
        created before overwriting.
    """
    dst = Path(path)
    if backup and dst.exists():
        backup_file(dst)
    atomic_write(dst, data)


# =============================================================================
# Directory helpers
# =============================================================================

def ensure_dir(path: "str | Path") -> Path:
    """Create *path* and all intermediate parents if they don't exist.

    Returns the resolved Path object.
    """
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    return p


# =============================================================================
# File info
# =============================================================================

def get_file_info(path: "str | Path") -> Dict[str, Any]:
    """Return a dictionary with metadata and integrity hashes for *path*.

    Keys
    ----
    ``path``        : str – absolute path
    ``size``        : int – size in bytes
    ``mtime``       : float – last-modified timestamp (epoch seconds)
    ``md5``         : str – MD5 hex digest
    ``sha1``        : str – SHA-1 hex digest
    ``sha256``      : str – SHA-256 hex digest
    ``is_binary``   : bool – True when the file contains non-text bytes

    Parameters
    ----------
    path : str | Path
        Target file. Must exist.

    Raises
    ------
    FileNotFoundError
        If the file does not exist.
    """
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"'{p}' not found")

    stat = p.stat()
    data = p.read_bytes()

    md5    = hashlib.md5(data).hexdigest()
    sha1   = hashlib.sha1(data).hexdigest()
    sha256 = hashlib.sha256(data).hexdigest()

    # Heuristic: presence of null bytes or bytes > 0x7E → binary
    is_binary = b"\x00" in data or any(b > 0x7E for b in data[:4096])

    return {
        "path":      str(p),
        "size":      stat.st_size,
        "mtime":     stat.st_mtime,
        "md5":       md5,
        "sha1":      sha1,
        "sha256":    sha256,
        "is_binary": is_binary,
    }
