# Bool Network

A Python implementation of the committee lifecycle from
*"Bool Network: An Open, Distributed, Secure Cross-chain Notary Platform"*
(Yin, Zhang, Xu, Lu, Ren; IACR ePrint 2022/1290). Four modules are integrated
into one pipeline that runs end to end:

| Stage | Module | What it does |
|---|---|---|
| 1. Sortition | `bool_net/ring_vrf.py`, `bool_net/sortition.py` | Nodes win committee seats with a Ring VRF proof. Winners publish an ephemeral public key (epk) |
| 2. Key generation | `bool_net/dkg.py` | creates a shared group key (distributed key generation). |
| 3. Handover | `bool_net/handover.py` | committee re-shares its key shares to the new committee. The group public key does not change. |
| 4. Signing | `bool_net/threshold_signing.py` | The current committee produces a threshold Schnorr signature. |
| Helper Files | `bool_net/epoch.py`, `bool_net/curve.py`, `bool_net/hybrid.py`, `bool_net/board.py` | Epoch orchestration, the shared secp256k1 group, share encryption and Chaum-Pedersen proofs, and an mock stand-in for the blockchain. |

## 1. Environment

### Software

| Requirement |
|---|
| Python |
| cryptography library |

### Hardware

No special hardware is needed. No GPU, no Intel SGX or other TEE, and no
network access at run time.

---

## 2. Installation

```bash
python3 -m venv .venv                 # optional but recommended
source .venv/bin/activate             # Windows: .venv\Scripts\activate
pip install cryptography
```

Check the install:

```bash
python -c "import cryptography, sys; print(sys.version.split()[0], cryptography.__version__)"
```

---

## 3. Project layout

```
Bool-Network/
├── README.md
├── main.py                   # 3-epoch end-to-end run (sortition -> DKG/handover -> sign)
├── demo.py                   # narrated demo: normal workflow + 4 security checks
├── test_integration.py       # 11 integration tests
└── bool_net/
    ├── curve.py              # secp256k1 helpers shared by all modules
    ├── board.py              # in-memory broadcast channel (blockchain stand-in)
    ├── hybrid.py             # ECDH + HKDF + AES-GCM share encryption; Chaum-Pedersen proof
    ├── ring_vrf.py           # Ring VRF
    ├── sortition.py          # try_win / verify_winner glue around Ring VRF
    ├── dkg.py                # DKG
    ├── handover.py           # committee handover with encrypted shares and complaints
    ├── threshold_signing.py  # threshold Schnorr
    └── epoch.py              # Network / Committee orchestrator and signing helper
```

---

## 4. Configuration

There are no configuration files, environment variables, credentials or API
keys. All parameters are constructor arguments of `Network` in
`bool_net/epoch.py`:

| Parameter | Default | Meaning |
|---|---|---|
| `num_nodes` | 12 | Number of registered nodes |
| `win_fraction` | `(3, 4)` | Each node wins sortition with probability 3/4. The threshold is `T = 2^256 * 3 // 4`. |
| `ring_size` | 4 | Size of the anonymity ring each winner proves membership in |
| `min_size` | 5 | Smallest acceptable committee. The beacon is redrawn until this is reached. |
| `max_size` | 7 | Largest committee. Extra winners with the highest VRF hashes are dropped. |
| `genesis` | `b"bool-genesis"` | Seed for the first beacon |

Example of a custom run:

```python
from bool_net.epoch import Network, sign
net = Network(num_nodes=8, ring_size=3, min_size=4, max_size=5)
committee = net.advance()                 # epoch 0: sortition + DKG
committee = net.advance()                 # epoch 1: sortition + handover
sig = sign(committee, b"hello")           # threshold signature, group key unchanged
```

---

## 5. Execution

All commands are run from the `Bool-Network/` directory.

```bash
python main.py
```
Runs three epochs

```bash
python demo.py
```

Takes about 30 s and prints PASS/FAIL lines. It has two parts:

**Part 1: normal workflow.** Anonymous committee election, DKG, a threshold
signature (and rejection of a tampered message), then a new committee,
handover, the same group key, a signature under the unchanged key, and erasure
of the old shares.

**Part 2: security checks.**

| Check | What happens | Expected result |
|---|---|---|
| A. Cheating dealer | An old member sends a corrupted share to a new seat | Dealer disqualified; handover still completes with the key preserved |
| B. False accuser | A new member falsely complains about an honest dealer | Dealer not disqualified; the accuser is identified |
| C. Stolen proof | A Ring VRF proof is copied and re-posted with another epk | Original accepted, copy rejected |
| D. Too few signers | 2 of a 3-threshold committee try to sign | Request rejected |

---

## 6. Testing

```bash
python -m unittest -v test_integration
```

| Test | What it verifies |
|---|---|
| `test_all_modules_share_one_group` | Ring VRF and the shared curve use the same group |
| `test_dkg_output_signs` | DKG shares produce a valid threshold signature |
| `test_dkg_cheater_disqualified` | A DKG dealer who cheats and refuses to reveal is excluded |
| `test_handover_preserves_key_and_signs` | Handover keeps the group key, the new committee signs, and the old and new reconstructed secrets match |
| `test_handover_can_change_threshold_and_size` | A 3-of-4 committee hands over to a 4-of-6 committee |
| `test_cheating_dealer_is_disqualified_and_handover_still_completes` | A bad share is detected and handover finishes with valid signing |
| `test_false_accusation_does_not_disqualify_honest_dealer` | A lying complainer is identified and the honest dealer survives |
| `test_forged_complaint_proof_is_rejected` | A complaint with a wrong DH point fails the Chaum-Pedersen check |
| `test_ring_vrf_proof_is_bound_to_epk` | A copied proof with a swapped epk, a tampered VRF hash, or an unregistered ring member is rejected |
| `test_invalid_parameters_are_rejected_with_clear_errors` | Invalid inputs raise the errors listed in Section 7 |
| `test_full_epochs_through_orchestrator` | Sortition, DKG and two handovers run through `Network`; the group key never changes and old shares are erased |

Run a single test:

```bash
python -m unittest -v test_integration.Integration.test_handover_preserves_key_and_signs
```

## 7. Authors' code, modifications, AI assistance

- **Source of the protocols:** the Bool Network paper (ePrint 2022/1290),
  implemented from its protocol descriptions.
- **Group-member modules:** DKG: Shymalan, handover: Agamjot, Ring VRF: Mayuresh and threshold signing: Aayush
- **AI assistance:** AI was used to integrate the different components developed by the team. Furthermore, the integration tests were written with assistance from AI. Code documentation and commenting was written with assisstance from AI, after which the group members edited and refined it further.

---

## 8. Limitations and differences from the paper

- **No TEE.** Key erasure is simulated by setting shares to `None`. The paper
  relies on Intel SGX to enforce erasure.
- **Simulated blockchain.** `Board` is an in-memory list. Messages are Python
  objects, so a real deployment needs a serialization layer.
- **Ring proof size.** The Ring VRF uses a one-out-of-N OR-proof, whose size
  and verification time are linear in ring size. The paper's one-out-of-many
  proof is logarithmic. This is acceptable for rings of 3 to 5.
- **DKG simplifications.** The DKG has no hash-commitment round and no
  two-phase broadcast, and disputes are settled by public reveal rather than a
  decryption-correctness proof.
- **Handover simplification.** Ciphertexts and commitments are posted in one
  message instead of two phases. The old committee's public partial-key table
  is taken as given rather than agreed by majority vote.
- **Signing.** Threshold Schnorr (one of the schemes the paper lists) is used.
  The paper's GG20 threshold ECDSA is not implemented.
- **Curve.** secp256k1 is used throughout instead of the paper's curve25519.
- **No stake locking, punishment, or network-layer anonymity.**
- **Security model.** Pure-Python arithmetic is not constant time. The paper
  proves security only against static corruption, and no formal proof is
  provided for this code.
- **Speed.** About 15 to 20 s per epoch for committees of 5 to 7.