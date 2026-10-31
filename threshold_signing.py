"""FIT5163 Bool Network: threshold Schnorr signing over secp256k1.

Each Signer holds only its own secret share; Coordinator holds public shares.
Requires a trusted authenticated channel and DKG-verified public shares.
This is Schnorr implementation.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from secrets import randbelow
from typing import Mapping, Sequence

"""
COMPONENT 1: SECP256K1 DOMAIN PARAMETERS
P is the curve field prime (point coordinates are reduced modulo P).
Q is the generator order (secret shares, nonce scalars and signatures use Q).
G is the standard secp256k1 generator. None represents the point at infinity.
CRITICAL INTEGRATION CONTRACT: DKG and handover must use this same curve, Q,
and compatible Shamir evaluation IDs; otherwise signature verification fails.
"""
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Point = tuple[int,int] | None


"""
COMPONENT 2: INPUT VALIDATION
Fail early on malformed parameters instead of continuing cryptographic work.
"""
def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)

"""
Check whether a value is a valid affine secp256k1 point (or infinity).
This is a mathematical curve-membership check, not authentication.
"""
def _on_curve(p: Point) -> bool:
    return p is None or (isinstance(p, tuple) and len(p)==2 and all(type(v) is int for v in p)
                          and 0 <= p[0] < P and 0 <= p[1] < P and p[1] * p[1] % P == (p[0]**3+7) % P)


"""
COMPONENT 3: ELLIPTIC-CURVE POINT ARITHMETIC
Add two curve points; None acts as the additive identity.
The slope differs between point doubling (a == b) and distinct points.
"""
def add(a: Point, b: Point) -> Point:
    _require(_on_curve(a) and _on_curve(b), "invalid curve point")
    if a is None: return b
    if b is None: return a
    x1,y1=a; x2,y2=b
    if x1==x2 and (y1+y2)%P==0: return None
    if a==b:
        lam=(3*x1*x1 * pow(2*y1, -1, P)) % P
    else:
        lam=((y2-y1)*pow((x2-x1)%P, -1, P))%P
    x3=(lam*lam-x1-x2)%P
    return (x3,(lam*(x1-x3)-y1)%P)


"""
Compute scalar multiplication k * p using binary double-and-add.
IMPORTANT: variable-time Python math is for academic demonstration, not for
production systems where timing side channels may reveal secret scalars.
"""
def mul(k: int, p: Point=G) -> Point:
    _require(type(k) is int and 0 <= k < Q, "scalar out of range")
    _require(_on_curve(p), "invalid curve point")
    out=None
    while k:
        if k & 1: out=add(out,p)
        p=add(p,p)
        k >>= 1
    return out


"""
Encode a non-identity point as SEC1 compressed bytes (33 bytes):
0x02/0x03 indicates y parity; the remaining 32 bytes store x.
"""
def encode_point(p: Point) -> bytes:
    _require(p is not None and _on_curve(p), "identity or invalid point")
    return (b'\x02' if p[1]%2==0 else b'\x03') + p[0].to_bytes(32,'big')


"""
Decode SEC1 compressed point bytes and recover y from the curve equation.
Reject noncanonical x coordinates and values that do not lie on the curve.
"""
def decode_point(data: bytes) -> Point:
    _require(isinstance(data,bytes) and len(data)==33 and data[0] in (2,3), "invalid compressed point encoding")
    x=int.from_bytes(data[1:],'big')
    _require(x<P, "point x coordinate out of range")
    y=pow((x*x*x+7)%P,(P+1)//4,P)
    if y%2 != data[0]%2: y=P-y
    p=(x,y)
    _require(_on_curve(p), "point is not on the curve")
    return p