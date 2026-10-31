"""
demo.py -- run this in the presentation and screenshot it for the report.

    python3 demo.py

Scenario 1: honest 5-member committee, threshold 3.
Scenario 2: party 2 cheats and ignores the complaint -> disqualified.
Scenario 3: timing as the committee grows (evidence for the evaluation).
Also writes dkg_output.json -- the file teammates load.
"""

import itertools
import time

from group import g_pow
from dkg import Party, run_dkg, reconstruct_secret, save_results


def short(x: int) -> str:
    h = hex(x)
    return h[:10] + "..." + h[-6:]


def scenario_honest() -> None:
    print("=" * 64)
    print("SCENARIO 1 -- honest committee (n=5, t=3)")
    print("=" * 64)
    results = run_dkg(5, 3)
    Y = results[0].group_public_key
    for r in results:
        print(f"  party {r.party_id}: share {short(r.secret_share)}   "
              f"public key {short(r.group_public_key)}")
    print(f"\n  All 5 parties agree on the public key: "
          f"{len({r.group_public_key for r in results}) == 1}")

    shares = {r.party_id: r.secret_share for r in results}
    ok = all(g_pow(reconstruct_secret({j: shares[j] for j in c})) == Y
             for c in itertools.combinations(shares, 3))
    print(f"  Every group of 3 shares matches the public key (10 groups): {ok}")
    two = reconstruct_secret({1: shares[1], 2: shares[2]})
    print(f"  Only 2 shares matches the public key: {g_pow(two) == Y}  (should be False)")

    save_results(results, "dkg_output.json")
    print("\n  Saved -> dkg_output.json (hand this to signing + handover)")


def scenario_cheater() -> None:
    print("\n" + "=" * 64)
    print("SCENARIO 2 -- party 2 sends a bad share to party 4 and stays silent")
    print("=" * 64)
    n, t = 5, 3
    parties = [Party(i, n, t) for i in range(1, n + 1)]
    parties[1].cheat_against = [4]
    parties[1].refuse_to_reveal = True
    results = run_dkg(n, t, parties)
    print(f"  Qualified set (QUAL): {results[0].qualified}")
    print(f"  Party 2 disqualified: {2 not in results[0].qualified}")
    shares = {r.party_id: r.secret_share for r in results}
    x = reconstruct_secret({j: shares[j] for j in (1, 3, 5)})
    print(f"  Remaining parties still produce a working key: "
          f"{g_pow(x) == results[0].group_public_key}")


def scenario_timing() -> None:
    print("\n" + "=" * 64)
    print("SCENARIO 3 -- how running time grows with committee size")
    print("=" * 64)
    print(f"  {'n':>4} {'t':>4} {'seconds':>10}")
    for n in (4, 8, 16, 32):
        t = n // 2 + 1
        start = time.perf_counter()
        run_dkg(n, t)
        print(f"  {n:>4} {t:>4} {time.perf_counter() - start:>10.3f}")
    print("  (Grows roughly with n^2 * t: each of n parties checks n shares,\n"
          "   each against t commitments.)")


if __name__ == "__main__":
    scenario_honest()
    scenario_cheater()
    scenario_timing()
