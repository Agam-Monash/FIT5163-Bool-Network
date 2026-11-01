# DKG component — Bool Network (FIT5163)

Owner: Shyamalan · Python 3.10+ · one dependency: `pip install cryptography`

## Files

| File | What it is |
|---|---|
| `group.py` | Shared group parameters `P, Q, G`. **Everyone imports these.** |
| `dkg.py` | Shamir sharing, Feldman verification, hybrid encryption, mock broadcast channel, the 4-phase DKG, and `DKGResult` (the hand-off object). |
| `test_dkg.py` | 15 automated tests: `python3 -m unittest -v test_dkg` |
| `demo.py` | Presentation demo (honest run, cheater, timing). Writes `dkg_output.json`. |
| `check_integration.py` | Proves the output works for threshold signing and handover. |

## Run

```
pip install cryptography
python3 -m unittest -v test_dkg
python3 demo.py
python3 check_integration.py
```

## Using the output (teammates)

```python
from group import P, Q, G, g_pow
from dkg import run_dkg, load_results, lagrange_coefficient

results = run_dkg(n=5, t=3)          # or: load_results("dkg_output.json")
me = results[0]
me.secret_share        # x_i  (int, private)
me.group_public_key    # Y    (int, same for everyone)
me.public_shares[j]    # Y_j = G^(x_j) for each qualified j
me.qualified           # list of honest party ids
me.threshold, me.n
lagrange_coefficient(i, signer_ids)   # weight for share i
```

## Simplifications vs. the paper

- No SGX/TEE: shares are protected by encryption in transit and by the party's own process, not by hardware.
- The broadcast channel is an in-memory list, not a blockchain.
- Disputes are resolved by the accused dealer revealing the share publicly (Pedersen/GJKR style) rather than a zero-knowledge proof of decryption.
- A 256-bit prime-order group is used instead of an elliptic curve (identical maths; easier to read).
