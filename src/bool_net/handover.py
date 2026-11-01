"""
handover.py -- committee handover (paper Fig. 11), integrated version.

Compared with the standalone sketch this adds the two things the paper needs
and the sketch left as stubs:
  1. shares travel ENCRYPTED to the next committee's sortition epks
  2. complaints carry a Chaum-Pedersen proof (hybrid.py), so a false
     accusation cannot get an honest dealer disqualified, and a lying
     complainer is identified.

Input  : the old committee's key shares (DKG or a previous handover) + the
         new committee's epks (from Ring VRF sortition).
Output : DKGResult ("KeyShare") objects for the new committee, same group key.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from cryptography.exceptions import InvalidTag

from .board import Board
from .curve import INF, Q, Point, add, eval_poly, is_valid_point, lagrange, rand_scalar, smul
from .dkg import DKGResult
from .hybrid import (decrypt_scalar, decrypt_with_secret, encrypt_scalar,
                     prove_dh, verify_dh)


def _aad(ctx: bytes, j: int, k: int) -> bytes:
    return ctx + b"|" + f"{j}->{k}".encode()


@dataclass
class DealerMsg:
    dealer: int
    cts: dict[int, dict]          # new seat k -> Enc_epk_k(sigma_{j,k})
    commitments: list[Point]      # A_{j,1..t2-1}   (A_{j,0} = ppk_j is public)


def feldman_check(sigma: int, k: int, commitments: list[Point], ppk_j: Point) -> bool:
    """g^sigma == ppk_j + sum_n k^n * A_{j,n}"""
    rhs = ppk_j
    for n, A in enumerate(commitments, start=1):
        rhs = add(rhs, smul(pow(k, n, Q), A))
    return smul(sigma) == rhs


@dataclass
class OldMember:
    idx: int
    psk: int
    t2: int
    c2: int
    epks: dict[int, Point]
    ctx: bytes
    cheat_against: set = field(default_factory=set)   # test knob: corrupt these seats' shares

    def deal(self) -> DealerMsg:
        coeffs = [self.psk % Q] + [rand_scalar() for _ in range(self.t2 - 1)]
        cts = {}
        for k in range(1, self.c2 + 1):
            s = eval_poly(coeffs, k)
            if k in self.cheat_against:
                s = (s + 1) % Q
            cts[k] = encrypt_scalar(s, self.epks[k], _aad(self.ctx, self.idx, k))
        return DealerMsg(self.idx, cts, [smul(a) for a in coeffs[1:]])


@dataclass
class NewMember:
    idx: int
    t1: int
    t2: int
    esk: int
    ctx: bytes
    false_complaint_against: set = field(default_factory=set)  # test knob

    def __post_init__(self) -> None:
        self.epk = smul(self.esk)
        self._sigma: dict[int, int] = {}
        self.npsk = 0

    def receive(self, msgs: dict[int, DealerMsg], ppk: dict[int, Point], board: Board) -> None:
        for j, m in msgs.items():
            blob = m.cts.get(self.idx)
            ok, s = False, None
            if blob is not None:
                try:
                    s = decrypt_scalar(blob, self.esk, _aad(self.ctx, j, self.idx))
                    ok = feldman_check(s, self.idx, m.commitments, ppk[j])
                except Exception:
                    ok = False
            if ok:
                self._sigma[j] = s
            if not ok or j in self.false_complaint_against:
                try:
                    S = smul(self.esk, blob["R"])
                    proof = prove_dh(self.esk, blob["R"], self.epk, S)
                except Exception:
                    continue          # malformed ciphertext: adjudicate() rejects the dealer structurally
                board.post(self.idx, "complaint", {"by": self.idx, "against": j, "S": S, "proof": proof})

    def finalize(self, msgs: dict[int, DealerMsg], disqualified: set[int]) -> list[int]:
        I = sorted(j for j in msgs if j not in disqualified)[: self.t1]
        if len(I) < self.t1:
            raise RuntimeError("not enough honest dealers; rerun handover")
        if any(j not in self._sigma for j in I):
            raise RuntimeError(f"seat {self.idx}: missing share from a dealer judged honest")
        self.npsk = sum(lagrange(j, I) * self._sigma[j] for j in I) % Q
        return I


def _struct_ok(m: DealerMsg, c2: int, t2: int) -> bool:
    return (set(m.cts) == set(range(1, c2 + 1))
            and len(m.commitments) == t2 - 1
            and all(is_valid_point(A) for A in m.commitments)
            and all(isinstance(b, dict) and is_valid_point(b.get("R")) for b in m.cts.values()))


def adjudicate(msgs: dict[int, DealerMsg], complaints: list[dict], ppk: dict[int, Point],
               epks: dict[int, Point], ctx: bytes, t2: int, c2: int) -> tuple[set[int], set[int]]:
    """PUBLIC deterministic judgement over the transcript. Returns
    (disqualified dealers, complainers caught lying)."""
    bad_dealers = {j for j, m in msgs.items() if not _struct_ok(m, c2, t2)}
    bad_complainers: set[int] = set()
    for c in complaints:
        j, k = c["against"], c["by"]
        if j in bad_dealers or j not in msgs or k not in epks:
            continue
        m = msgs[j]
        if not verify_dh(epks[k], m.cts[k]["R"], c["S"], c["proof"]):
            bad_complainers.add(k)    # S not provably the real DH secret -> ignore, punish
            continue
        try:
            sigma = decrypt_with_secret(m.cts[k], c["S"], _aad(ctx, j, k))
            dealer_lied = not feldman_check(sigma, k, m.commitments, ppk[j])
        except InvalidTag:
            dealer_lied = True
        if dealer_lied:
            bad_dealers.add(j)
        else:
            bad_complainers.add(k)    # share was fine: false accusation
    return bad_dealers, bad_complainers


def new_partial_pubkeys(msgs, ppk, I, c2) -> dict[int, Point]:
    """nppk_k = sum_{j in I} lambda_j * (ppk_j + sum_n k^n A_{j,n}); public data only."""
    lam = {j: lagrange(j, I) for j in I}
    out = {}
    for k in range(1, c2 + 1):
        acc = INF
        for j in I:
            gs = ppk[j]
            for n, A in enumerate(msgs[j].commitments, start=1):
                gs = add(gs, smul(pow(k, n, Q), A))
            acc = add(acc, smul(lam[j], gs))
        out[k] = acc
    return out


def check_group_key(nppk: dict[int, Point], gpk: Point, t2: int) -> bool:
    """Public sanity check: any t2 new partial keys must interpolate to the OLD gpk."""
    ids = list(range(1, t2 + 1))
    acc = INF
    for k in ids:
        acc = add(acc, smul(lagrange(k, ids), nppk[k]))
    return acc == gpk


@dataclass
class HandoverReport:
    disqualified: set
    bad_complainers: set
    dealers_used: list


def run_handover(old: list[OldMember], new: list[NewMember], ppk: dict[int, Point],
                 gpk: Point, ctx: bytes, board: Board | None = None):
    board = board or Board()
    c2, t2, t1 = len(new), new[0].t2, new[0].t1
    epks = {m.idx: m.epk for m in new}

    for o in old:                                   # phase 1: deal
        board.post(o.idx, "deal", o.deal())
    msgs = {d["from"]: d["payload"] for d in board.read("deal")}

    for m in new:                                   # phase 2: verify + complain
        m.receive(msgs, ppk, board)
    bad_d, bad_c = adjudicate(msgs, [c["payload"] for c in board.read("complaint")],
                              ppk, epks, ctx, t2, c2)

    for m in new:                                   # phase 3: combine
        I = m.finalize(msgs, bad_d)
    nppk = new_partial_pubkeys(msgs, ppk, I, c2)

    if not check_group_key(nppk, gpk, t2):
        raise RuntimeError("handover changed the group public key -- abort")
    for m in new:
        if smul(m.npsk) != nppk[m.idx]:
            raise RuntimeError(f"seat {m.idx}: share inconsistent with public partial key")

    results = [DKGResult(m.idx, m.npsk, gpk, nppk, list(range(1, c2 + 1)), t2, c2) for m in new]
    return results, HandoverReport(bad_d, bad_c, I)
