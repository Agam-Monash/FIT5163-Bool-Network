"""
hybrid.py -- share encryption TO a sortition ephemeral public key, plus the
Chaum-Pedersen proof used for complaints.

Paper: shares are encrypted under the next committee member's epk. Ring VRF
winners publish epk as a secp256k1 point, so we do ECDH on secp256k1
(replacing the X25519 keys the original dkg.py generated internally):

    encrypt:  r random, R = r*G, S = r*epk, key = HKDF(S), AES-GCM(share)
    decrypt:  S = esk*R

Complaint (paper's "NIZK of decryption correctness"): the receiver reveals S
and proves log_G(epk) == log_R(S) (= esk). Anyone can then decrypt the blob
with S themselves and judge whether the dealer or the complainer is lying --
without the receiver ever revealing esk.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .curve import G, Q, add, enc, hash_to_scalar, is_valid_point, neg, rand_scalar, smul


def _key(S) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"bool-net-share").derive(enc(S))


def encrypt_scalar(m: int, recipient_epk, aad: bytes) -> dict:
    r = rand_scalar()
    R, S = smul(r), smul(r, recipient_epk)
    nonce = os.urandom(12)
    ct = AESGCM(_key(S)).encrypt(nonce, (m % Q).to_bytes(32, "big"), aad)
    return {"R": R, "nonce": nonce, "ct": ct}


def decrypt_with_secret(blob: dict, S, aad: bytes) -> int:
    """Decrypt using the DH point S (raises InvalidTag on forgery/garbage)."""
    pt = AESGCM(_key(S)).decrypt(blob["nonce"], blob["ct"], aad)
    return int.from_bytes(pt, "big")


def decrypt_scalar(blob: dict, esk: int, aad: bytes) -> int:
    return decrypt_with_secret(blob, smul(esk, blob["R"]), aad)


# ---- Chaum-Pedersen: prove log_G(epk) == log_R(S) --------------------------

def _challenge(epk, R, S, A1, A2) -> int:
    return hash_to_scalar(b"cp-dh", enc(epk), enc(R), enc(S), enc(A1), enc(A2))


def prove_dh(esk: int, R, epk, S) -> tuple[int, int]:
    t = rand_scalar()
    c = _challenge(epk, R, S, smul(t), smul(t, R))
    return c, (t + c * esk) % Q


def verify_dh(epk, R, S, proof) -> bool:
    try:
        c, z = proof
        if not (is_valid_point(epk) and is_valid_point(R) and is_valid_point(S)):
            return False
        A1 = add(smul(z), neg(smul(c, epk)))
        A2 = add(smul(z, R), neg(smul(c, S)))
        return c == _challenge(epk, R, S, A1, A2)
    except (TypeError, ValueError):
        return False
