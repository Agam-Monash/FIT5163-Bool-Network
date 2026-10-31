"""
check_integration.py -- proves dkg_output.json is usable by the other
components. These are SMOKE TESTS of the hand-off contract, not the
teammates' implementations (those live in their own files).

    python3 demo.py               # creates dkg_output.json
    python3 check_integration.py
"""

import hashlib

from group import P, Q, g_pow, random_scalar
from dkg import load_results, lagrange_coefficient, make_polynomial, eval_polynomial


def H(*parts: int) -> int:
    data = b"".join(x.to_bytes(64, "big") for x in parts)
    return int.from_bytes(hashlib.sha256(data).digest(), "big") % Q


results = load_results("dkg_output.json")
Y = results[0].group_public_key
t = results[0].threshold

# --- 1. Threshold signing can use the shares (Schnorr, t signers) ----------
signers = results[:t]
idx = [r.party_id for r in signers]
msg = 123456789
nonces = {r.party_id: random_scalar() for r in signers}
R = 1
for k in nonces.values():
    R = (R * g_pow(k)) % P
e = H(R, Y, msg)
partials = {}
for r in signers:
    lam = lagrange_coefficient(r.party_id, idx)
    partials[r.party_id] = (nonces[r.party_id] + e * lam * r.secret_share) % Q
    # each partial is checkable against that signer's PUBLIC share
    Yi = r.public_shares[r.party_id]
    assert g_pow(partials[r.party_id]) == (g_pow(nonces[r.party_id]) * pow(Yi, e * lam, P)) % P
z = sum(partials.values()) % Q
sig_ok = g_pow(z) == (R * pow(Y, e, P)) % P
print(f"[signing]  {t} parties produced a valid signature under the group key: {sig_ok}")

# --- 2. Handover can move the key to a new committee without changing Y ----
new_n, new_t = 4, 2
new_shares = {k: 0 for k in range(1, new_n + 1)}
for r in signers:  # t old members each re-deal their weighted share
    lam = lagrange_coefficient(r.party_id, idx)
    f = make_polynomial(lam * r.secret_share, new_t)
    for k in new_shares:
        new_shares[k] = (new_shares[k] + eval_polynomial(f, k)) % Q
from dkg import reconstruct_secret
x_new = reconstruct_secret({k: new_shares[k] for k in (1, 3)})
handover_ok = g_pow(x_new) == Y
print(f"[handover] new committee's shares still match the SAME public key: {handover_ok}")

assert sig_ok and handover_ok
print("\nHand-off contract verified.")
