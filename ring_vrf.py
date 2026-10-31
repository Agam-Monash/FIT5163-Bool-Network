"""
Ring VRF & Anonymous Sortition Module 
=====================================================================
Paper: Bool Network: An Open, Distributed, Secure Cross-chain Notary Platform

Features Implemented:
1. Pedersen Commitments: C = g^m * h^r (mod p)
2. Hash-to-Curve PRF & VRF Evaluation: v = H(seed)^{sk}
3. Ring-Anonymous NIZK Proof (Fiat-Shamir transformed 1-out-of-N ZK Proof)
4. Cryptographic Sortition Check: v < Threshold
5. Ephemeral Key Pair Generation & Committee Broadcast Payload

All implementation uses SECP256k1 curve arithmetic (pure Python implementation)
for 100% zero-dependency execution and full reproducibility.
"""

import hashlib
import secrets
from typing import List, Tuple, Optional, Dict

# ------------------------------------------------------------------------------
# SECP256k1 Curve Constants & Point Arithmetic
# ------------------------------------------------------------------------------
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Secondary Generator H for Pedersen Commitments
Hx = 0x240A26123213D6E503180477218683A354E18151480D92637E4399990833C716
Hy = 0x6A1B2D9D810AEF28379B48E6ADAE016B6187965F256E1054C349F2CE57F1C9B7

Point = Optional[Tuple[int, int]]  # None represents Point at Infinity (0)
G: Point = (Gx, Gy)
H_GEN: Point = (Hx, Hy)

def point_add(p1: Point, p2: Point) -> Point:
    """Adds two points on SECP256k1 curve."""
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and y1 != y2:
        return None
    if x1 == x2:
        m = (3 * x1 * x1 + A) * pow(2 * y1, P - 2, P) % P
    else:
        m = (y2 - y1) * pow(x2 - x1, P - 2, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)

def point_mul(p: Point, k: int) -> Point:
    """Scalar multiplication k * P on SECP256k1 curve."""
    if p is None:
        return None
    k = k % N
    if k == 0:
        return None
    result: Point = None
    addend = p
    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1
    return result

def encode_point(p: Point) -> bytes:
    """Encodes a curve point into 33-byte compressed format."""
    if p is None:
        return b'\x00' * 33
    x, y = p
    prefix = b'\x02' if y % 2 == 0 else b'\x03'
    return prefix + x.to_bytes(32, 'big')

def hash_to_curve(data: bytes) -> Point:
    """Hash-to-Curve mapping: Hashes byte payload to a valid SECP256k1 point."""
    counter = 0
    while True:
        h = hashlib.sha256(data + counter.to_bytes(4, 'big')).digest()
        x = int.from_bytes(h, 'big') % P
        y_sq = (pow(x, 3, P) + B) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if pow(y, 2, P) == y_sq:
            return (x, y)
        counter += 1

# ------------------------------------------------------------------------------
# 1. Pedersen Commitment Primitive
# ------------------------------------------------------------------------------
class PedersenCommitment:
    """
    Pedersen Commitment scheme: C = m*G + r*H
    Properties: Perfect Hiding, Computational Binding.
    """
    @staticmethod
    def commit(message: int, blinding_factor: Optional[int] = None) -> Tuple[Point, int]:
        if blinding_factor is None:
            blinding_factor = secrets.randbelow(N - 1) + 1
        c1 = point_mul(G, message % N)
        c2 = point_mul(H_GEN, blinding_factor % N)
        commitment = point_add(c1, c2)
        return commitment, blinding_factor

    @staticmethod
    def verify(commitment: Point, message: int, blinding_factor: int) -> bool:
        c1 = point_mul(G, message % N)
        c2 = point_mul(H_GEN, blinding_factor % N)
        expected = point_add(c1, c2)
        return commitment == expected

# ------------------------------------------------------------------------------
# 2. Ring VRF Core Protocol
# ------------------------------------------------------------------------------
class RingVRF:
    """
    Ring Verifiable Random Function (RVRF) with Anonymous Sortition.
    """
    def __init__(self, secret_key: int):
        self.sk = secret_key % N
        self.pk: Point = point_mul(G, self.sk)

    @staticmethod
    def generate_keypair() -> Tuple[int, Point]:
        """Generates a secret key and public key pair."""
        sk = secrets.randbelow(N - 1) + 1
        pk = point_mul(G, sk)
        return sk, pk

    def evaluate_vrf(self, epoch_seed: bytes) -> Tuple[Point, bytes]:
        """
        Evaluates VRF output point V = sk * H(epoch_seed)
        Returns (VRF_Point, VRF_Hash_Bytes)
        """
        h_pt = hash_to_curve(epoch_seed)
        v_pt = point_mul(h_pt, self.sk)
        vrf_hash = hashlib.sha256(encode_point(v_pt) + epoch_seed).digest()
        return v_pt, vrf_hash

    def prove_ring_vrf(
        self,
        epoch_seed: bytes,
        ring: List[Point]
    ) -> Dict:
        """
        Generates a 1-out-of-N Ring-Anonymous Zero-Knowledge Proof (Fiat-Shamir transformed).
        Proves that the prover knows sk corresponding to some pk in ring R,
        such that V = sk * H(epoch_seed), without revealing which pk in R belongs to prover.
        """
        if self.pk not in ring:
            raise ValueError("Prover's public key must be included in the candidate ring!")

        n_ring = len(ring)
        my_idx = ring.index(self.pk)
        h_pt = hash_to_curve(epoch_seed)
        v_pt = point_mul(h_pt, self.sk)

        c_list = [0] * n_ring
        z_list = [0] * n_ring
        a_list = [None] * n_ring
        b_list = [None] * n_ring

        # Prover's real random nonce
        alpha = secrets.randbelow(N - 1) + 1
        a_list[my_idx] = point_mul(G, alpha)
        b_list[my_idx] = point_mul(h_pt, alpha)

        # Simulate nonces for all other ring members
        for i in range(n_ring):
            if i != my_idx:
                c_list[i] = secrets.randbelow(N - 1) + 1
                z_list[i] = secrets.randbelow(N - 1) + 1
                
                # a_i = z_i * G - c_i * PK_i
                term1_a = point_mul(G, z_list[i])
                term2_a = point_mul(ring[i], (N - c_list[i]) % N)
                a_list[i] = point_add(term1_a, term2_a)

                # b_i = z_i * H(x) - c_i * V
                term1_b = point_mul(h_pt, z_list[i])
                term2_b = point_mul(v_pt, (N - c_list[i]) % N)
                b_list[i] = point_add(term1_b, term2_b)

        # Compute Fiat-Shamir global challenge C
        hasher = hashlib.sha256()
        hasher.update(epoch_seed)
        hasher.update(encode_point(v_pt))
        for pk in ring:
            hasher.update(encode_point(pk))
        for i in range(n_ring):
            hasher.update(encode_point(a_list[i]))
            hasher.update(encode_point(b_list[i]))
        
        global_c = int.from_bytes(hasher.digest(), 'big') % N

        # Compute prover's real challenge c_my_idx so that sum(c_i) = global_c
        sum_other_c = sum(c_list[i] for i in range(n_ring) if i != my_idx) % N
        c_list[my_idx] = (global_c - sum_other_c) % N

        # Compute prover's real response z_my_idx = alpha + c_my_idx * sk
        z_list[my_idx] = (alpha + c_list[my_idx] * self.sk) % N

        proof = {
            "v_pt": v_pt,
            "c_list": c_list,
            "z_list": z_list,
            "epoch_seed": epoch_seed,
            "ring": ring
        }
        return proof

    @staticmethod
    def verify_ring_vrf(proof: Dict) -> bool:
        """
        Verifies the Ring-Anonymous NIZK Proof.
        """
        v_pt = proof["v_pt"]
        c_list = proof["c_list"]
        z_list = proof["z_list"]
        epoch_seed = proof["epoch_seed"]
        ring = proof["ring"]
        n_ring = len(ring)

        if len(c_list) != n_ring or len(z_list) != n_ring:
            return False

        h_pt = hash_to_curve(epoch_seed)
        a_list = [None] * n_ring
        b_list = [None] * n_ring

        for i in range(n_ring):
            # Reconstruct a_i = z_i * G - c_i * PK_i
            term1_a = point_mul(G, z_list[i])
            term2_a = point_mul(ring[i], (N - c_list[i]) % N)
            a_list[i] = point_add(term1_a, term2_a)

            # Reconstruct b_i = z_i * H(x) - c_i * V
            term1_b = point_mul(h_pt, z_list[i])
            term2_b = point_mul(v_pt, (N - c_list[i]) % N)
            b_list[i] = point_add(term1_b, term2_b)

        # Re-compute global challenge C
        hasher = hashlib.sha256()
        hasher.update(epoch_seed)
        hasher.update(encode_point(v_pt))
        for pk in ring:
            hasher.update(encode_point(pk))
        for i in range(n_ring):
            hasher.update(encode_point(a_list[i]))
            hasher.update(encode_point(b_list[i]))

        expected_global_c = int.from_bytes(hasher.digest(), 'big') % N
        actual_global_c = sum(c_list) % N

        return expected_global_c == actual_global_c

# ------------------------------------------------------------------------------
# 3. Cryptographic Sortition & Ephemeral Key Broadcast
# ------------------------------------------------------------------------------
class CryptographicSortition:
    """
    Determines committee selection based on VRF output and difficulty threshold T.
    """
    @staticmethod
    def is_selected(vrf_hash: bytes, difficulty_threshold: int) -> bool:
        """
        Returns True if int(vrf_hash) < difficulty_threshold.
        """
        val = int.from_bytes(vrf_hash, 'big')
        return val < difficulty_threshold

    @staticmethod
    def generate_committee_payload(
        vrf_proof: Dict,
        vrf_hash: bytes
    ) -> Dict:
        """
        Generates broadcast payload with a fresh ephemeral keypair (epk, esk)
        for anonymous committee participation.
        """
        esk, epk = RingVRF.generate_keypair()
        payload = {
            "vrf_proof": vrf_proof,
            "vrf_hash": vrf_hash.hex(),
            "ephemeral_pk": encode_point(epk).hex(),
            "ephemeral_sk_secret": esk
        }
        return payload

# ------------------------------------------------------------------------------
# Self-Test Execution / Benchmark
# ------------------------------------------------------------------------------
if __name__ == "__main__":
    print("==========================================================")
    print("Testing Ring VRF & Anonymous Sortition Module (Member A)")
    print("==========================================================")

    # 1. Pedersen Commitment Self-Test
    print("\n[1] Testing Pedersen Commitments...")
    msg = 42
    comm, r = PedersenCommitment.commit(msg)
    valid_comm = PedersenCommitment.verify(comm, msg, r)
    invalid_comm = PedersenCommitment.verify(comm, msg + 1, r)
    print(f" -> Pedersen Commitment Verified: {valid_comm}")
    assert valid_comm is True
    assert invalid_comm is False

    # 2. Setup Ring of Candidate Notaries
    print("\n[2] Setting up Candidate Ring (5 Notary Candidates)...")
    ring_sks = []
    ring_pks = []
    for _ in range(5):
        sk, pk = RingVRF.generate_keypair()
        ring_sks.append(sk)
        ring_pks.append(pk)

    # Member A is Candidate #2 in the Ring
    my_sk = ring_sks[2]
    my_rvrf = RingVRF(my_sk)
    epoch_seed = b"Epoch_2026_Block_1048576"

    # 3. Evaluate VRF and Generate Ring Proof
    print("\n[3] Evaluating VRF & Generating 1-out-of-N Anonymous Proof...")
    v_pt, vrf_hash = my_rvrf.evaluate_vrf(epoch_seed)
    proof = my_rvrf.prove_ring_vrf(epoch_seed, ring_pks)
    print(f" -> VRF Output Point: {encode_point(v_pt).hex()[:32]}...")
    print(f" -> VRF Hash: {vrf_hash.hex()[:32]}...")

    # 4. Verify Ring VRF Proof
    print("\n[4] Verifying Ring VRF Proof...")
    is_valid_proof = RingVRF.verify_ring_vrf(proof)
    print(f" -> Proof Verification Result: {is_valid_proof}")
    assert is_valid_proof is True

    # 5. Cryptographic Sortition Check
    print("\n[5] Cryptographic Sortition Check...")
    difficulty_threshold = (1 << 255)
    selected = CryptographicSortition.is_selected(vrf_hash, difficulty_threshold)
    print(f" -> Selected for Hidden Committee? {selected}")

    if selected:
        payload = CryptographicSortition.generate_committee_payload(proof, vrf_hash)
        print(" -> Ephemeral Key Generated for Committee Broadcast:")
        print(f"    epk: {payload['ephemeral_pk']}")

    print("\nAll unit tests passed successfully!")
