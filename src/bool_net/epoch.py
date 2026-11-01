"""
epoch.py -- the orchestrator: one object that runs the paper's epoch loop.

    registration -> Ring-VRF sortition -> (epoch 0: DKG | later: handover)
                 -> threshold signing -> erase old shares -> next epoch

Everything is simulated in one process (nodes are objects, the chain is a
Board). The module boundaries are real though: each stage only consumes the
public output type of the previous one.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from . import dkg as dkgmod
from . import handover as ho
from .board import Board
from .curve import Point, enc
from .ring_vrf import RingVRF
from .sortition import try_win, verify_winner
from .threshold_signing import Coordinator, Signature, Signer, verify

_rng = secrets.SystemRandom()


def threshold_for(n: int) -> int:
    """Policy knob: honest-majority threshold. (Paper's testnet used 10-of-15.)"""
    return max(2, n // 2 + 1)


@dataclass
class Node:
    name: str
    sk: int
    pk: Point

    def __post_init__(self) -> None:
        self.rvrf = RingVRF(self.sk)


@dataclass
class Member:
    node: Node
    seat: int
    esk: int | None            # epoch-ephemeral secret (erased after handover)
    epk: Point
    share: dkgmod.KeyShare | None = None


@dataclass
class Committee:
    epoch: int
    members: dict[int, Member]
    threshold: int
    gpk: Point | None = None
    public_shares: dict[int, Point] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return len(self.members)

    @property
    def epks(self) -> dict[int, Point]:
        return {s: m.epk for s, m in self.members.items()}


class Network:
    def __init__(self, num_nodes: int = 12, win_fraction: tuple[int, int] = (3, 4),
                 ring_size: int = 4, min_size: int = 5, max_size: int = 7,
                 genesis: bytes = b"bool-genesis") -> None:
        sks = [RingVRF.generate_keypair() for _ in range(num_nodes)]
        self.nodes = [Node(f"node{i}", sk, pk) for i, (sk, pk) in enumerate(sks)]
        self.registry = {n.pk for n in self.nodes}               # registration (stake locking omitted)
        self.T = (1 << 256) * win_fraction[0] // win_fraction[1]  # winning threshold
        self.ring_size, self.min_size, self.max_size = ring_size, min_size, max_size
        self.beacon = hashlib.sha256(genesis).digest()
        self.committee: Committee | None = None
        self.epoch = -1

    # -- sortition ----------------------------------------------------------
    def elect(self, epoch: int) -> Committee:
        reg = list(self.registry)
        for attempt in range(50):    # committee size is random; re-draw the beacon if too small
            seed = hashlib.sha256(self.beacon + epoch.to_bytes(8, "big") + attempt.to_bytes(4, "big")).digest()
            chain, private = Board(), {}
            for node in self.nodes:
                ring = _rng.sample([p for p in reg if p != node.pk], self.ring_size - 1) + [node.pk]
                _rng.shuffle(ring)                                   # position must not reveal the prover
                won = try_win(node.rvrf, seed, ring, self.T)
                if won:
                    payload, esk = won
                    chain.post("anon", "winner", payload)            # no sender identity on-chain
                    private[enc(payload["epk"])] = (node, esk)
            valid, seen_v = [], set()
            for m in chain.read("winner"):                           # chain-side verification
                p = m["payload"]
                v = enc(p["proof"]["v_pt"])
                if verify_winner(p, seed, self.T, self.registry) and v not in seen_v:
                    seen_v.add(v)
                    valid.append(p)
            if len(valid) >= self.min_size:
                break
        else:
            raise RuntimeError("sortition never produced a large enough committee")
        valid = sorted(valid, key=lambda p: p["vrf_hash"])[: self.max_size]   # cap: lowest hashes win
        valid.sort(key=lambda p: enc(p["epk"]))                               # public, deterministic seats
        members = {}
        for seat, p in enumerate(valid, start=1):
            node, esk = private[enc(p["epk"])]
            members[seat] = Member(node, seat, esk, p["epk"])
        self.beacon = hashlib.sha256(seed + b"next").digest()
        return Committee(epoch, members, threshold_for(len(members)))

    # -- key management -----------------------------------------------------
    def _genesis_dkg(self, c: Committee) -> None:
        ctx = b"bool-dkg|epoch|" + str(c.epoch).encode()
        parties = [dkgmod.Party(s, c.size, c.threshold, esk=m.esk, ctx=ctx) for s, m in c.members.items()]
        results = dkgmod.run_dkg(c.size, c.threshold, parties)
        assert len({r.group_public_key for r in results}) == 1
        for r in results:
            c.members[r.party_id].share = r
        c.gpk, c.public_shares = results[0].group_public_key, results[0].public_shares

    def _handover(self, old: Committee, new: Committee):
        ctx = b"bool-handover|epoch|" + str(new.epoch).encode()
        olds = [ho.OldMember(j, m.share.secret_share, new.threshold, new.size, new.epks, ctx)
                for j, m in old.members.items()]
        news = [ho.NewMember(k, old.threshold, new.threshold, m.esk, ctx) for k, m in new.members.items()]
        results, report = ho.run_handover(olds, news, old.public_shares, old.gpk, ctx)
        for r in results:
            new.members[r.party_id].share = r
        new.gpk, new.public_shares = old.gpk, results[0].public_shares
        for m in old.members.values():          # TEE-enforced erasure in the real system
            m.share, m.esk = None, None
        return report

    # -- one epoch ----------------------------------------------------------
    def advance(self) -> Committee:
        self.epoch += 1
        new = self.elect(self.epoch)
        if self.committee is None:
            self._genesis_dkg(new)
        else:
            self.last_report = self._handover(self.committee, new)
        self.committee = new
        return new


# -- signing (threshold Schnorr) ---------------------------------------------

def sign(c: Committee, message: bytes, seats: list[int] | None = None) -> Signature:
    seats = seats or sorted(c.members)[: c.threshold]
    gpk_b = enc(c.gpk)
    coord = Coordinator(gpk_b, {k: enc(v) for k, v in c.public_shares.items()}, c.threshold)
    signers = [Signer(s, c.members[s].share.secret_share) for s in seats]
    sid = secrets.token_bytes(32)
    pkg = coord.package(sid, message, [s.commit(sid) for s in signers])
    sig = coord.aggregate(pkg, [s.sign(pkg) for s in signers])
    assert verify(message, sig, gpk_b)
    return sig
