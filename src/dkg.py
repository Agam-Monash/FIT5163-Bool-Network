"""
dkg.py -- Distributed Key Generation (DKG) for the Bool Network project.
Owner: Shyamalan.

WHAT DKG DOES, IN ONE SENTENCE
------------------------------
n committee members jointly create ONE shared key pair, where the public key
is known to everyone but the private key is never held by anybody: each
member only holds a "share", and any t of them together can use it (sign),
while t-1 or fewer learn nothing.

THE ANALOGY
-----------
Each member writes a secret number, cuts it into n puzzle pieces with
Shamir's trick, and posts each piece to a different member in a locked
envelope. Everyone also pins a public "fingerprint" (Feldman commitments)
on the noticeboard so a receiver can check their piece is genuine without
seeing anyone else's. Each member then adds up the pieces they received.
The group's secret = sum of everyone's secret numbers -- but nobody ever
adds those up, so nobody ever knows it.

PROTOCOL (Pedersen-style DKG with Feldman verification)
-------------------------------------------------------
Phase 1 -- Deal
    Every party i picks a random polynomial f_i of degree t-1.
    It broadcasts commitments  C_ik = G^(a_ik)  for each coefficient,
    and broadcasts each share s_ij = f_i(j) ENCRYPTED to party j
    (hybrid encryption: X25519 + HKDF + AES-GCM), so it can sit on a
    public channel such as a blockchain.
Phase 2 -- Verify & complain
    Every party j decrypts the shares addressed to it and checks
        G^(s_ij) == product_k  C_ik ^ (j^k)        (Feldman check)
    A failed check -> broadcast a complaint against dealer i.
Phase 3 -- Resolve
    An accused dealer must publicly reveal the disputed share. If the
    revealed share still fails the check (or the dealer stays silent),
    the dealer is DISQUALIFIED. Everyone else forms the set QUAL.
Phase 4 -- Combine
    Party j's final secret share:  x_j = sum_{i in QUAL} s_ij  mod Q
    Group public key:             Y   = product_{i in QUAL} C_i0
    Public share of party j:      Y_j = G^(x_j)   (computable by anyone)

The output each party hands to the signing and handover code is a
DKGResult (see bottom of file) and can be saved to JSON.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from group import P, Q, G, g_pow, random_scalar


# ---------------------------------------------------------------------------
# 1. Shamir secret sharing (polynomials mod Q)
# ---------------------------------------------------------------------------

def make_polynomial(secret: int, t: int) -> list[int]:
    """Random polynomial of degree t-1 whose constant term is `secret`.
    coeffs[0] is the secret; t points are needed to rebuild it."""
    return [secret % Q] + [random_scalar() for _ in range(t - 1)]


def eval_polynomial(coeffs: list[int], x: int) -> int:
    """f(x) mod Q using Horner's rule (work from the top coefficient down)."""
    result = 0
    for c in reversed(coeffs):
        result = (result * x + c) % Q
    return result


def lagrange_coefficient(i: int, indices: list[int]) -> int:
    """Weight for share i when rebuilding f(0) from the shares in `indices`.

        lambda_i = product over j != i of  j / (j - i)   (mod Q)

    TEAMMATES: threshold signing and handover both need this function.
    """
    if i not in indices:
        raise ValueError("i must be one of the indices")
    num, den = 1, 1
    for j in indices:
        if j == i:
            continue
        num = (num * j) % Q
        den = (den * (j - i)) % Q
    return (num * pow(den, -1, Q)) % Q


def reconstruct_secret(shares: dict[int, int]) -> int:
    """Rebuild f(0) from {index: share}. FOR TESTING ONLY -- in the real
    system nobody ever reassembles the group secret in one place."""
    idx = list(shares)
    return sum(shares[i] * lagrange_coefficient(i, idx) for i in idx) % Q


# ---------------------------------------------------------------------------
# 2. Feldman verifiable secret sharing
# ---------------------------------------------------------------------------

def commit_polynomial(coeffs: list[int]) -> list[int]:
    """Public fingerprints C_k = G^(a_k). Reveal nothing about a_k
    (discrete-log problem) but let anyone check a share."""
    return [g_pow(a) for a in coeffs]


def expected_public_share(commitments: list[int], j: int) -> int:
    """Compute G^(f(j)) from the commitments alone:
        product_k  C_k ^ (j^k)  mod P"""
    result = 1
    for k, C in enumerate(commitments):
        result = (result * pow(C, pow(j, k, Q), P)) % P
    return result


def verify_share(share: int, j: int, commitments: list[int]) -> bool:
    """Feldman check: is `share` really f(j) for the committed polynomial?"""
    return g_pow(share) == expected_public_share(commitments, j)


# ---------------------------------------------------------------------------
# 3. Hybrid encryption so shares can travel over a PUBLIC channel
# ---------------------------------------------------------------------------

def _derive_key(shared_secret: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None, info=b"bool-dkg-share"
    ).derive(shared_secret)


def _pub_bytes(pk: X25519PublicKey) -> bytes:
    return pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def encrypt_share(share: int, recipient_pk: X25519PublicKey, aad: bytes) -> dict:
    """Ephemeral X25519 + HKDF + AES-GCM. `aad` binds the ciphertext to
    (dealer, recipient) so it can't be replayed to someone else."""
    eph = X25519PrivateKey.generate()
    key = _derive_key(eph.exchange(recipient_pk))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, share.to_bytes(32, "big"), aad)
    return {"eph_pk": _pub_bytes(eph.public_key()).hex(), "nonce": nonce.hex(), "ct": ct.hex()}


def decrypt_share(blob: dict, recipient_sk: X25519PrivateKey, aad: bytes) -> int:
    eph_pk = X25519PublicKey.from_public_bytes(bytes.fromhex(blob["eph_pk"]))
    key = _derive_key(recipient_sk.exchange(eph_pk))
    pt = AESGCM(key).decrypt(bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["ct"]), aad)
    return int.from_bytes(pt, "big")


# ---------------------------------------------------------------------------
# 4. A mock public broadcast channel (stands in for the blockchain)
# ---------------------------------------------------------------------------

class BroadcastChannel:
    """Every message posted here is visible to every party, in order.
    In Bool Network this role is played by the blockchain."""

    def __init__(self) -> None:
        self.messages: list[dict] = []

    def post(self, sender: int, kind: str, payload: dict) -> None:
        self.messages.append({"from": sender, "kind": kind, "payload": payload})

    def read(self, kind: str) -> list[dict]:
        return [m for m in self.messages if m["kind"] == kind]


# ---------------------------------------------------------------------------
# 5. Output handed to teammates
# ---------------------------------------------------------------------------

@dataclass
class DKGResult:
    """What ONE party walks away with. This is the hand-off contract.

    party_id          -- this party's index (1..n). Never 0: f(0) is the secret.
    secret_share      -- x_j, this party's PRIVATE share. Keep secret.
    group_public_key  -- Y = G^x, the shared public key (same for everyone).
    public_shares     -- {j: Y_j = G^(x_j)} for every qualified party.
                         Used to check each signer's partial signature.
    qualified         -- indices of parties that finished DKG honestly.
    threshold         -- t: how many shares are needed to sign.
    n                 -- committee size.
    """

    party_id: int
    secret_share: int
    group_public_key: int
    public_shares: dict[int, int]
    qualified: list[int]
    threshold: int
    n: int

    def to_dict(self, include_secret: bool = True) -> dict:
        d = {
            "party_id": self.party_id,
            "group_public_key": hex(self.group_public_key),
            "public_shares": {str(k): hex(v) for k, v in self.public_shares.items()},
            "qualified": self.qualified,
            "threshold": self.threshold,
            "n": self.n,
        }
        if include_secret:
            d["secret_share"] = hex(self.secret_share)
        return d

    @staticmethod
    def from_dict(d: dict) -> "DKGResult":
        return DKGResult(
            party_id=d["party_id"],
            secret_share=int(d["secret_share"], 16),
            group_public_key=int(d["group_public_key"], 16),
            public_shares={int(k): int(v, 16) for k, v in d["public_shares"].items()},
            qualified=list(d["qualified"]),
            threshold=d["threshold"],
            n=d["n"],
        )


# ---------------------------------------------------------------------------
# 6. A committee member
# ---------------------------------------------------------------------------

@dataclass
class Party:
    pid: int
    n: int
    t: int
    # behaviour switches used to demonstrate the complaint mechanism
    cheat_against: list[int] = field(default_factory=list)  # send bad shares to these
    refuse_to_reveal: bool = False                           # stay silent when accused
    false_accuse: list[int] = field(default_factory=list)    # complain about honest dealers

    def __post_init__(self) -> None:
        self.enc_sk = X25519PrivateKey.generate()
        self.enc_pk = self.enc_sk.public_key()
        self._coeffs: list[int] = []
        self._sent_shares: dict[int, int] = {}
        self._received: dict[int, int] = {}

    # Phase 1 ---------------------------------------------------------------
    def deal(self, channel: BroadcastChannel, directory: dict[int, X25519PublicKey]) -> None:
        self._coeffs = make_polynomial(random_scalar(), self.t)
        commitments = commit_polynomial(self._coeffs)
        encrypted = {}
        for j in range(1, self.n + 1):
            s = eval_polynomial(self._coeffs, j)
            if j in self.cheat_against:
                s = (s + 1) % Q  # deliberately corrupt this share
            self._sent_shares[j] = s
            aad = f"{self.pid}->{j}".encode()
            encrypted[str(j)] = encrypt_share(s, directory[j], aad)
        channel.post(self.pid, "deal", {"commitments": [hex(c) for c in commitments],
                                        "shares": encrypted})

    # Phase 2 ---------------------------------------------------------------
    def verify_and_complain(self, channel: BroadcastChannel) -> None:
        for msg in channel.read("deal"):
            dealer = msg["from"]
            commitments = [int(c, 16) for c in msg["payload"]["commitments"]]
            blob = msg["payload"]["shares"][str(self.pid)]
            try:
                s = decrypt_share(blob, self.enc_sk, f"{dealer}->{self.pid}".encode())
                ok = verify_share(s, self.pid, commitments)
            except Exception:
                s, ok = None, False
            if ok and dealer not in self.false_accuse:
                self._received[dealer] = s
            else:
                channel.post(self.pid, "complaint", {"against": dealer})

    # Phase 3 ---------------------------------------------------------------
    def answer_complaints(self, channel: BroadcastChannel) -> None:
        for c in channel.read("complaint"):
            if c["payload"]["against"] == self.pid and not self.refuse_to_reveal:
                accuser = c["from"]
                channel.post(self.pid, "reveal",
                             {"to": accuser, "share": hex(self._sent_shares[accuser])})

    # Phase 4 ---------------------------------------------------------------
    def finalise(self, channel: BroadcastChannel) -> DKGResult:
        commitments = {m["from"]: [int(c, 16) for c in m["payload"]["commitments"]]
                       for m in channel.read("deal")}
        qualified = disqualify(channel, commitments)

        # Accept publicly revealed shares that turned out valid.
        for r in channel.read("reveal"):
            if r["payload"]["to"] == self.pid and r["from"] in qualified:
                self._received[r["from"]] = int(r["payload"]["share"], 16)

        x_j = sum(self._received[i] for i in qualified) % Q

        # Multiply all qualified dealers' commitments together, coefficient by
        # coefficient. The result commits to the SUM polynomial F = sum f_i,
        # whose F(0) is the group secret and F(j) is party j's share.
        combined = [1] * self.t
        for i in qualified:
            for k in range(self.t):
                combined[k] = (combined[k] * commitments[i][k]) % P

        Y = combined[0]
        public_shares = {j: expected_public_share(combined, j) for j in qualified}
        return DKGResult(self.pid, x_j, Y, public_shares, qualified, self.t, self.n)


def disqualify(channel: BroadcastChannel, commitments: dict[int, list[int]]) -> list[int]:
    """Deterministic rule every honest party applies to the SAME public
    transcript, so they all agree on QUAL without talking further."""
    bad = set()
    reveals = {(r["from"], r["payload"]["to"]): int(r["payload"]["share"], 16)
               for r in channel.read("reveal")}
    for c in channel.read("complaint"):
        dealer, accuser = c["payload"]["against"], c["from"]
        revealed = reveals.get((dealer, accuser))
        if revealed is None or not verify_share(revealed, accuser, commitments[dealer]):
            bad.add(dealer)
    return sorted(i for i in commitments if i not in bad)


# ---------------------------------------------------------------------------
# 7. Run the whole protocol
# ---------------------------------------------------------------------------

def run_dkg(n: int, t: int, parties: list[Party] | None = None,
            channel: BroadcastChannel | None = None) -> list[DKGResult]:
    """Run all four phases for an n-member committee with threshold t.
    Returns one DKGResult per party (index 0 -> party 1, etc.)."""
    if not 1 <= t <= n:
        raise ValueError("need 1 <= t <= n")
    parties = parties or [Party(i, n, t) for i in range(1, n + 1)]
    channel = channel or BroadcastChannel()
    directory = {p.pid: p.enc_pk for p in parties}

    for p in parties:
        p.deal(channel, directory)
    for p in parties:
        p.verify_and_complain(channel)
    for p in parties:
        p.answer_complaints(channel)
    results = [p.finalise(channel) for p in parties]

    if len(results[0].qualified) < t:
        raise RuntimeError("Too many dealers disqualified: fewer than t remain.")
    return results


def save_results(results: list[DKGResult], path: str) -> None:
    with open(path, "w") as f:
        json.dump({"group": {"P": hex(P), "Q": hex(Q), "G": G},
                   "parties": [r.to_dict() for r in results]}, f, indent=2)


def load_results(path: str) -> list[DKGResult]:
    with open(path) as f:
        data = json.load(f)
    return [DKGResult.from_dict(d) for d in data["parties"]]
