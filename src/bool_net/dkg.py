"""
dkg.py -- Pedersen-style DKG with Feldman verification (Shyamalan's design),
PORTED to the shared secp256k1 group.

What changed vs. the original (protocol logic is the same, 4 phases):
  * group: mod-p Schnorr group -> secp256k1 (so shares are valid inputs for
    threshold signing and handover). `G^x` is now `smul(x)`, products of
    group elements are point additions.
  * encryption: shares are encrypted to each party's `enc_pk`, which is now a
    secp256k1 point (the sortition epk) instead of a locally generated X25519 key.
  * public_shares are computed for ALL parties 1..n (the original only did it for
    qualified ones, which would leave a disqualified dealer's share without a
    public key for the signing coordinator).
  * finalise() now verifies a revealed share against the dealer's commitments
    before accepting it (otherwise a dealer could overwrite someone's good
    share with a bad one by posting an unsolicited "reveal").
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .board import Board
from .curve import (INF, Point, Q, add, decode_point, enc, eval_poly, lagrange,
                    make_poly, rand_scalar, reconstruct, smul)
from .hybrid import decrypt_scalar, encrypt_scalar

# names the original modules / check_integration.py used
make_polynomial = make_poly
eval_polynomial = eval_poly
lagrange_coefficient = lagrange
reconstruct_secret = reconstruct
BroadcastChannel = Board


# ---- Feldman VSS ------------------------------------------------------------

def commit_polynomial(coeffs: list[int]) -> list[Point]:
    return [smul(a) for a in coeffs]


def expected_public_share(commitments: list[Point], j: int) -> Point:
    """G^f(j) from commitments alone: sum_k  j^k * C_k."""
    acc = INF
    for k, C in enumerate(commitments):
        acc = add(acc, smul(pow(j, k, Q), C))
    return acc


def verify_share(share: int, j: int, commitments: list[Point]) -> bool:
    return smul(share) == expected_public_share(commitments, j)


# ---- hand-off object --------------------------------------------------------

@dataclass
class DKGResult:
    """What ONE party walks away with. Also the output format of handover, so
    `KeyShare` is the single type the signing code consumes."""
    party_id: int
    secret_share: int
    group_public_key: Point
    public_shares: dict[int, Point]
    qualified: list[int]
    threshold: int
    n: int

    def to_dict(self, include_secret: bool = True) -> dict:
        d = {"party_id": self.party_id, "group_public_key": enc(self.group_public_key).hex(),
             "public_shares": {str(k): enc(v).hex() for k, v in self.public_shares.items()},
             "qualified": self.qualified, "threshold": self.threshold, "n": self.n}
        if include_secret:
            d["secret_share"] = hex(self.secret_share)
        return d

    @staticmethod
    def from_dict(d: dict) -> "DKGResult":
        return DKGResult(d["party_id"], int(d["secret_share"], 16),
                         decode_point(bytes.fromhex(d["group_public_key"])),
                         {int(k): decode_point(bytes.fromhex(v)) for k, v in d["public_shares"].items()},
                         list(d["qualified"]), d["threshold"], d["n"])


KeyShare = DKGResult


# ---- a committee member -----------------------------------------------------

@dataclass
class Party:
    pid: int
    n: int
    t: int
    esk: int | None = None           # sortition ephemeral secret key (None -> fresh)
    ctx: bytes = b"bool-dkg"         # domain separation (e.g. epoch number)
    cheat_against: list[int] = field(default_factory=list)
    refuse_to_reveal: bool = False
    false_accuse: list[int] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.enc_sk = self.esk if self.esk is not None else rand_scalar()
        self.enc_pk = smul(self.enc_sk)
        self._coeffs: list[int] = []
        self._sent_shares: dict[int, int] = {}
        self._received: dict[int, int] = {}

    def _aad(self, dealer: int, rcpt: int) -> bytes:
        return self.ctx + b"|" + f"{dealer}->{rcpt}".encode()

    def deal(self, channel: Board, directory: dict[int, Point]) -> None:
        self._coeffs = make_poly(rand_scalar(), self.t)
        commitments = commit_polynomial(self._coeffs)
        encrypted = {}
        for j in range(1, self.n + 1):
            s = eval_poly(self._coeffs, j)
            if j in self.cheat_against:
                s = (s + 1) % Q
            self._sent_shares[j] = s
            encrypted[j] = encrypt_scalar(s, directory[j], self._aad(self.pid, j))
        channel.post(self.pid, "deal", {"commitments": commitments, "shares": encrypted})

    def verify_and_complain(self, channel: Board) -> None:
        for msg in channel.read("deal"):
            dealer, p = msg["from"], msg["payload"]
            try:
                s = decrypt_scalar(p["shares"][self.pid], self.enc_sk, self._aad(dealer, self.pid))
                ok = verify_share(s, self.pid, p["commitments"])
            except Exception:
                s, ok = None, False
            if ok and dealer not in self.false_accuse:
                self._received[dealer] = s
            else:
                channel.post(self.pid, "complaint", {"against": dealer})

    def answer_complaints(self, channel: Board) -> None:
        for c in channel.read("complaint"):
            if c["payload"]["against"] == self.pid and not self.refuse_to_reveal:
                accuser = c["from"]
                channel.post(self.pid, "reveal",
                             {"to": accuser, "share": self._sent_shares[accuser]})

    def finalise(self, channel: Board) -> DKGResult:
        commitments = {m["from"]: m["payload"]["commitments"] for m in channel.read("deal")}
        qualified = disqualify(channel, commitments)
        for r in channel.read("reveal"):
            d = r["from"]
            if (r["payload"]["to"] == self.pid and d in qualified
                    and verify_share(r["payload"]["share"], self.pid, commitments[d])):
                self._received[d] = r["payload"]["share"]
        x_j = sum(self._received[i] for i in qualified) % Q

        combined = [INF] * self.t
        for i in qualified:
            for k in range(self.t):
                combined[k] = add(combined[k], commitments[i][k])
        public_shares = {j: expected_public_share(combined, j) for j in range(1, self.n + 1)}
        return DKGResult(self.pid, x_j, combined[0], public_shares, qualified, self.t, self.n)


def disqualify(channel: Board, commitments: dict[int, list[Point]]) -> list[int]:
    bad = set()
    reveals = {(r["from"], r["payload"]["to"]): r["payload"]["share"] for r in channel.read("reveal")}
    for c in channel.read("complaint"):
        dealer, accuser = c["payload"]["against"], c["from"]
        revealed = reveals.get((dealer, accuser))
        if revealed is None or not verify_share(revealed, accuser, commitments[dealer]):
            bad.add(dealer)
    return sorted(i for i in commitments if i not in bad)


def run_dkg(n: int, t: int, parties: list[Party] | None = None,
            channel: Board | None = None) -> list[DKGResult]:
    if not 1 <= t <= n:
        raise ValueError("need 1 <= t <= n")
    parties = parties or [Party(i, n, t) for i in range(1, n + 1)]
    channel = channel or Board()
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
        json.dump({"curve": "secp256k1", "parties": [r.to_dict() for r in results]}, f, indent=2)


def load_results(path: str) -> list[DKGResult]:
    with open(path) as f:
        return [DKGResult.from_dict(d) for d in json.load(f)["parties"]]
