"""Disposable smoke identities: run-derived seeds and RFC 8032 public keys (stdlib only).

The seeds are derived from public run metadata. They are throw-away test identities
that protect nothing: the Server allowlist admits exactly one such client key and
forwards only to a local echo fixture. They are never uploaded.
"""

import hashlib
import os
from pathlib import Path

_P = 2**255 - 19
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        raise ValueError("not a curve point")
    return _P - x if (x & 1) != sign else x


def _add(p1, p2):
    a = (p1[1] - p1[0]) * (p2[1] - p2[0]) % _P
    b = (p1[1] + p1[0]) * (p2[1] + p2[0]) % _P
    c = 2 * p1[3] * p2[3] * _D % _P
    d = 2 * p1[2] * p2[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(scalar, point):
    acc = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            acc = _add(acc, point)
        point = _add(point, point)
        scalar >>= 1
    return acc


_GY = 4 * pow(5, _P - 2, _P) % _P
_GX = _recover_x(_GY, 0)
_BASE = (_GX, _GY, 1, _GX * _GY % _P)


def public_key(seed):
    """RFC 8032 Ed25519 public key of a 32-byte seed."""
    if not isinstance(seed, bytes) or len(seed) != 32:
        raise ValueError("seed must be exactly 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(digest[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    x, y, z, _ = _mul(scalar, _BASE)
    zinv = pow(z, _P - 2, _P)
    x, y = x * zinv % _P, y * zinv % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def derive_seed(run_id, attempt, role):
    """Per-run, per-role seed; distinct roles never collide."""
    if role not in ("server", "client"):
        raise ValueError("unknown role")
    material = b"\0".join((b"shaar-public-smoke/v1", run_id.encode("ascii"),
                           attempt.encode("ascii"), role.encode("ascii")))
    return hashlib.sha256(material).digest()


def derive_nonce(run_id, attempt):
    """Sixteen lowercase hex characters naming this run's single APP exchange."""
    material = b"\0".join((b"shaar-public-smoke/v1/nonce", run_id.encode("ascii"), attempt.encode("ascii")))
    return hashlib.sha256(material).hexdigest()[:16]


def write_key_file(path, seed):
    """Exclusive 0600 raw-seed file, as the products require."""
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(seed)
    return Path(path)
