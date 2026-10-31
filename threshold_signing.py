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