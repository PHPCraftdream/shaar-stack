"""Bounded DATA readers shared by the registry replay modules (stdlib only)."""

import hashlib
import re
import stat


def digest(data):
    return hashlib.sha256(data).hexdigest()


def bounded_regular(path, cap):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > cap:
        raise ValueError(f"Not a bounded regular file: {path}")
    with path.open("rb") as stream:
        data = stream.read(cap + 1)
    if len(data) != metadata.st_size or len(data) > cap:
        raise ValueError(f"Bounded read mismatch: {path}")
    return data


def safe_relative_path(value):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/") or re.match(r"^[A-Za-z]:", value):
        raise ValueError(f"Unsafe relative path: {value!r}")
    parts = value.split("/")
    if any(part in ("", ".", "..") or "\x00" in part for part in parts):
        raise ValueError(f"Unsafe path component: {value!r}")
    return parts


def no_link_path(root, relative):
    parts = safe_relative_path(relative)
    current = root
    for part in parts:
        current = current / part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"Symlink in DATA path: {current}")
    return current
