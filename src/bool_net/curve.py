"""
curve.py -- the ONE group every module uses: secp256k1.

Why this file exists: the original unintegrated modules used three different "languages"
for the same maths (a mod-p Schnorr group in DKG, the `ecdsa` library in
handover, hand-rolled tuples in ring_vrf / threshold). everything now
imports from here. Points are (x, y) tuples, None = point at infinity
"""
from __future__ import annotations

import hashlib
from secrets import randbelow

# threshold_signing.py is the reference implementation of the curve.
from .threshold_signing import (
    P, Q, G, Point, add, decode_point, lagrange, _on_curve,
    encode_point as _enc, mul as _mul,
)

INF: Point = None


def smul(k: int, p: Point = G) -> Point:
    """k*p for ANY integer k (reduced mod Q). threshold's mul() demands 0<=k<Q."""
    return _mul(k % Q, p)


def neg(p: Point) -> Point:
    return None if p is None else (p[0], (-p[1]) % P)


def sub(a: Point, b: Point) -> Point:
    return add(a, neg(b))


def is_valid_point(p) -> bool:
    """True for a finite point on the curve (rejects None / junk)."""
    try:
        return p is not None and _on_curve(p)
    except Exception:
        return False


def enc(p: Point) -> bytes:
    """33-byte SEC1 encoding; infinity -> 33 zero bytes (never raises)."""
    return b"\x00" * 33 if p is None else _enc(p)


def rand_scalar() -> int:
    return 1 + randbelow(Q - 1)


def hash_to_scalar(tag: bytes, *chunks: bytes) -> int:
    h = hashlib.sha256(b"bool-net/" + tag)
    for c in chunks:
        h.update(len(c).to_bytes(8, "big"))
        h.update(c)
    return int.from_bytes(h.digest(), "big") % Q


# ---- Shamir helpers (shared by DKG and handover) --------------------------

def make_poly(secret: int, t: int) -> list[int]:
    """Random degree t-1 polynomial with constant term `secret`."""
    return [secret % Q] + [rand_scalar() for _ in range(t - 1)]


def eval_poly(coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % Q
    return acc


def reconstruct(shares: dict[int, int]) -> int:
    """TESTING ONLY: nobody reassembles the group secret in the real system."""
    ids = list(shares)
    return sum(lagrange(i, ids) * s for i, s in shares.items()) % Q
