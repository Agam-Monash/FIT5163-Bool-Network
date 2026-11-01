"""
demo.py -- narrated demo for the recording.   python demo.py

Part 1  normal workflow : sortition -> DKG -> sign -> handover -> sign (same key)
Part 2  security checks : cheating dealer, false accusation, stolen proof,
                          below-threshold signing
"""
import secrets
import time

from bool_net import dkg, handover as ho, ring_vrf
from bool_net.curve import enc, rand_scalar, smul
from bool_net.epoch import Network, sign
from bool_net.hybrid import prove_dh
from bool_net.sortition import try_win, verify_winner
from bool_net.threshold_signing import Coordinator, Signer, Signature, verify


def hdr(text):
    print("\n" + "=" * 70 + f"\n{text}\n" + "=" * 70)


def short(b: bytes) -> str:
    return b.hex()[:12] + "..."


def ok(flag: bool) -> str:
    return "PASS" if flag else "FAIL"


# Part 1
hdr("PART 1 -- NORMAL WORKFLOW")
net = Network(num_nodes=8, ring_size=3, min_size=4, max_size=5)
print(f"{len(net.nodes)} registered nodes, ring size {net.ring_size}, winning threshold T = 3/4 of 2^256")

t0 = time.time()
c0 = net.advance()
hdr("EPOCH 0: Ring-VRF sortition + DKG")
print(f"Committee elected anonymously: n={c0.size}, threshold t={c0.threshold}")
print("What the chain sees (ephemeral keys only, no identities):")
for seat, m in c0.members.items():
    print(f"  seat {seat}: epk {short(enc(m.epk))}")
print(f"DKG finished. Group public key: {short(enc(c0.gpk))}  (no one holds the group secret)")
msg0 = b"epoch 0: release 1 BTC to Alice"
sig0 = sign(c0, msg0)
gpk_b = enc(c0.gpk)
print(f"Threshold signature (t={c0.threshold} signers) valid:      {ok(verify(msg0, sig0, gpk_b))}")
print(f"Same signature on a TAMPERED message is rejected:   {ok(not verify(msg0 + b'!', sig0, gpk_b))}")
print(f"[{time.time() - t0:.0f}s]")

t0 = time.time()
old_members = list(c0.members.values())
c1 = net.advance()
hdr("EPOCH 1: new committee + HANDOVER")
print(f"New committee elected: n={c1.size}, threshold t={c1.threshold}")
print(f"Dealers used in handover: {net.last_report.dealers_used}, disqualified: {net.last_report.disqualified or 'none'}")
print(f"Group public key unchanged:  {short(enc(c1.gpk))}  -> {ok(c1.gpk == c0.gpk)}")
msg1 = b"epoch 1: release 2 BTC to Bob"
sig1 = sign(c1, msg1)
print(f"New committee signature valid under the SAME key:    {ok(verify(msg1, sig1, gpk_b))}")
print(f"Old committee's shares erased:                      {ok(all(m.share is None for m in old_members))}")
print(f"[{time.time() - t0:.0f}s]")

# ---------------------------------------------------------------- Part 2
hdr("PART 2 -- SECURITY FUNCTIONALITY")
old = dkg.run_dkg(4, 3)                       # small 3-of-4 committee for the attack demos
ppk, gpk, ctx = old[0].public_shares, old[0].group_public_key, b"demo"


def committee(c2, t2):
    esks = {k: rand_scalar() for k in range(1, c2 + 1)}
    return [ho.NewMember(k, 3, t2, esks[k], ctx) for k in esks]


def dealers(new, t2, cheat=None):
    epks = {m.idx: m.epk for m in new}
    return [ho.OldMember(r.party_id, r.secret_share, t2, len(new), epks, ctx,
                         cheat_against=(cheat or {}).get(r.party_id, set())) for r in old]


print("\n[A] Malicious old member 2 sends a corrupted share to new seat 1")
new = committee(4, 3)
res, rep = ho.run_handover(dealers(new, 3, {2: {1}}), new, ppk, gpk, ctx)
print(f"    Feldman check fails -> dealer(s) disqualified: {rep.disqualified}")
print(f"    Handover still completes and key preserved: {ok(all(r.group_public_key == gpk for r in res))}")

print("\n[B] Malicious new member 1 falsely accuses honest dealer 1")
new = committee(4, 3)
new[0].false_complaint_against = {1}
res, rep = ho.run_handover(dealers(new, 3), new, ppk, gpk, ctx)
print(f"    Chaum-Pedersen proof lets everyone check the share -> it was fine")
print(f"    Honest dealer disqualified: {rep.disqualified or 'no'};  liar identified: seat {rep.bad_complainers}")

print("\n[C] Attacker copies a winner's Ring-VRF proof and swaps in their own key")
keys = [ring_vrf.RingVRF.generate_keypair() for _ in range(4)]
registry, ring = {pk for _, pk in keys}, [pk for _, pk in keys]
seed, T = b"epoch seed", 1 << 256
payload, _ = try_win(ring_vrf.RingVRF(keys[0][0]), seed, ring, T)
stolen = dict(payload, epk=ring_vrf.RingVRF.generate_keypair()[1])
print(f"    Original proof accepted:       {ok(verify_winner(payload, seed, T, registry))}")
print(f"    Stolen proof (swapped epk) rejected: {ok(not verify_winner(stolen, seed, T, registry))}")

print("\n[D] Fewer than t members try to sign")
r0 = old[0]
coord = Coordinator(enc(gpk), {k: enc(v) for k, v in r0.public_shares.items()}, r0.threshold)
sid = secrets.token_bytes(32)
two = [Signer(i, old[i - 1].secret_share) for i in (1, 2)]
try:
    coord.package(sid, b"steal funds", [s.commit(sid) for s in two])
    print("    FAIL: signing proceeded")
except ValueError as e:
    print(f"    Rejected ({len(two)} of t={r0.threshold} signers): {ok(True)}  [{e}]")

hdr("DEMO COMPLETE")
