"""
sortition.py -- glue between Ring VRF and the rest of the system.

Fixes three gaps in using ring_vrf.py's pieces directly:
  * the proof now commits to the winner's epk (via the patched `tag`), so a
    copied proof cannot be re-posted with the attacker's own epk;
  * the verifier RECOMPUTES the VRF hash from the proven point v_pt instead of
    trusting the `vrf_hash` field (otherwise anyone could claim a winning hash);
  * the secret esk is never part of the broadcast payload.
"""
from __future__ import annotations

import hashlib

from .curve import enc, is_valid_point
from .ring_vrf import CryptographicSortition, RingVRF

MIN_RING = 3


def try_win(rvrf: RingVRF, seed: bytes, ring: list, T: int):
    """Returns (public_payload, esk) if this node wins the sortition, else None."""
    _, vrf_hash = rvrf.evaluate_vrf(seed)
    if not CryptographicSortition.is_selected(vrf_hash, T):
        return None
    esk, epk = RingVRF.generate_keypair()
    proof = rvrf.prove_ring_vrf(seed, ring, tag=enc(epk))
    return {"proof": proof, "vrf_hash": vrf_hash, "epk": epk}, esk


def verify_winner(payload: dict, seed: bytes, T: int, registry: set) -> bool:
    """Chain-side check of a published sortition claim."""
    try:
        proof, epk = payload["proof"], payload["epk"]
        ring = proof["ring"]
        if proof["epoch_seed"] != seed or proof.get("tag") != enc(epk):
            return False
        if len(ring) < MIN_RING or len(set(ring)) != len(ring) or any(pk not in registry for pk in ring):
            return False
        if not (is_valid_point(proof["v_pt"]) and is_valid_point(epk)):
            return False
        if not RingVRF.verify_ring_vrf(proof):
            return False
        h = hashlib.sha256(enc(proof["v_pt"]) + seed).digest()
        return h == payload["vrf_hash"] and CryptographicSortition.is_selected(h, T)
    except (KeyError, TypeError, ValueError):
        return False
