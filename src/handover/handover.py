"""
Committee handover as shown in:
"Bool Network: An Open, Distributed, Secure Cross-chain Notary Platform"
(Yin, Zhang, Xu, Lu, Ren; ePrint 2022/1290).
"""
import secrets
from dataclasses import dataclass, field

from ecdsa import SECP256k1
from ecdsa.ellipticcurve import INFINITY

# generator
G = SECP256k1.generator
# group of order Q
Q = SECP256k1.order

# Modular Inverse needed for lagrange denominators
def inv(a: int) -> int:
    return pow(a, -1, Q)

# evaluate polynomial using horners method
def eval_poly(coeffs: list[int], x: int) -> int:
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % Q
    return acc

# computes λⱼ = ∏ ℓ/(ℓ−j)
def lagrange_at_zero(indices: list[int], j: int) -> int:
    num, den = 1, 1
    for l in indices:
        if l == j:
            continue
        num = num * l % Q
        den = den * (l - j) % Q
    return num * inv(den) % Q

# reconstruct to recover secret
def reconstruct(shares: dict[int, int]) -> int:
    idx = list(shares)
    return sum(lagrange_at_zero(idx, j) * s for j, s in shares.items()) % Q


# all msgs published by dealer
@dataclass
class DealerMsg:
    dealer: int                      
    shares: dict[int, int]           
    commitments: list                

# class representing an old member
@dataclass
class OldMember:
    idx: int          
    psk: int          
    t2: int
    c2: int
    # functin for handling any dealings the member does
    def deal(self) -> DealerMsg:
        coeffs = [self.psk] + [secrets.randbelow(Q) for _ in range(self.t2 - 1)]
        shares = {k: eval_poly(coeffs, k) for k in range(1, self.c2 + 1)}
        commitments = [G * a for a in coeffs[1:]]
        return DealerMsg(self.idx, shares, commitments)

def feldman_check(msg: DealerMsg, k: int, ppk_j) -> bool:
    rhs = ppk_j
    for n, A in enumerate(msg.commitments, start=1):
        rhs = rhs + A * pow(k, n, Q)
    return G * msg.shares[k] == rhs


@dataclass
class NewMember:
    idx: int
    t1: int
    npsk: int = 0
    complaints: set = field(default_factory=set)

    def receive(self, msgs: dict[int, DealerMsg], ppk: dict[int, object]):
        for j, m in msgs.items():
            if not feldman_check(m, self.idx, ppk[j]):
                self.complaints.add(j)

    def finalize(self, msgs: dict[int, DealerMsg], disqualified: set[int]):
        valid = sorted(j for j in msgs if j not in disqualified)
        if len(valid) < self.t1:
            raise RuntimeError("not enough honest dealers; rerun handover")
        I = valid[: self.t1]
        self.npsk = sum(
            lagrange_at_zero(I, j) * msgs[j].shares[self.idx] for j in I
        ) % Q
        return I


def new_partial_pubkeys(msgs, ppk, I, c2):
    out = {}
    for k in range(1, c2 + 1):
        acc = INFINITY
        for j in I:
            gs = ppk[j]
            for n, A in enumerate(msgs[j].commitments, start=1):
                gs = gs + A * pow(k, n, Q)
            acc = acc + gs * lagrange_at_zero(I, j)
        out[k] = acc
    return out

def run_handover(old_shares: dict[int, int], t1: int, t2: int, c2: int,
                 tamper: set[int] = frozenset()):
    ppk = {j: G * s for j, s in old_shares.items()}
    old = [OldMember(j, s, t2, c2) for j, s in old_shares.items()]

    msgs = {m.idx: m.deal() for m in old}
    for j in tamper:
        msgs[j].shares[1] = (msgs[j].shares[1] + 1) % Q
    new = [NewMember(k, t1) for k in range(1, c2 + 1)]
    for m in new:
        m.receive(msgs, ppk)
    disqualified = set().union(*(m.complaints for m in new))
    I = None
    for m in new:
        I = m.finalize(msgs, disqualified)
    nppk = new_partial_pubkeys(msgs, ppk, I, c2)
    return new, nppk, disqualified