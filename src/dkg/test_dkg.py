"""
test_dkg.py -- automated checks. Run with:   python3 -m unittest -v test_dkg
Each test name says, in plain English, the security property it proves.
"""

import itertools
import os
import tempfile
import unittest

from group import P, Q, G, g_pow, random_scalar
from dkg import (
    Party, run_dkg, make_polynomial, eval_polynomial, reconstruct_secret,
    commit_polynomial, verify_share, encrypt_share, decrypt_share,
    lagrange_coefficient, save_results, load_results,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


class TestShamir(unittest.TestCase):
    def test_any_t_shares_rebuild_the_secret(self):
        secret, t, n = random_scalar(), 3, 5
        f = make_polynomial(secret, t)
        shares = {j: eval_polynomial(f, j) for j in range(1, n + 1)}
        for combo in itertools.combinations(shares, t):
            self.assertEqual(reconstruct_secret({j: shares[j] for j in combo}), secret)

    def test_t_minus_1_shares_do_not_rebuild_the_secret(self):
        secret, t = random_scalar(), 3
        f = make_polynomial(secret, t)
        two = {1: eval_polynomial(f, 1), 2: eval_polynomial(f, 2)}
        self.assertNotEqual(reconstruct_secret(two), secret)


class TestFeldman(unittest.TestCase):
    def test_honest_share_passes(self):
        f = make_polynomial(random_scalar(), 3)
        C = commit_polynomial(f)
        self.assertTrue(verify_share(eval_polynomial(f, 4), 4, C))

    def test_tampered_share_is_caught(self):
        f = make_polynomial(random_scalar(), 3)
        C = commit_polynomial(f)
        self.assertFalse(verify_share((eval_polynomial(f, 4) + 1) % Q, 4, C))


class TestEncryption(unittest.TestCase):
    def test_round_trip(self):
        sk = X25519PrivateKey.generate()
        s = random_scalar()
        blob = encrypt_share(s, sk.public_key(), b"1->2")
        self.assertEqual(decrypt_share(blob, sk, b"1->2"), s)

    def test_wrong_recipient_cannot_decrypt(self):
        sk, other = X25519PrivateKey.generate(), X25519PrivateKey.generate()
        blob = encrypt_share(random_scalar(), sk.public_key(), b"1->2")
        with self.assertRaises(Exception):
            decrypt_share(blob, other, b"1->2")

    def test_ciphertext_cannot_be_redirected(self):
        sk = X25519PrivateKey.generate()
        blob = encrypt_share(random_scalar(), sk.public_key(), b"1->2")
        with self.assertRaises(Exception):
            decrypt_share(blob, sk, b"1->3")


class TestDKG(unittest.TestCase):
    def test_everyone_agrees_on_the_public_key(self):
        results = run_dkg(5, 3)
        self.assertEqual(len({r.group_public_key for r in results}), 1)

    def test_each_public_share_matches_its_secret_share(self):
        for r in run_dkg(5, 3):
            self.assertEqual(g_pow(r.secret_share), r.public_shares[r.party_id])

    def test_any_t_parties_hold_the_matching_private_key(self):
        results = run_dkg(5, 3)
        Y = results[0].group_public_key
        shares = {r.party_id: r.secret_share for r in results}
        for combo in itertools.combinations(shares, 3):
            x = reconstruct_secret({j: shares[j] for j in combo})
            self.assertEqual(g_pow(x), Y)

    def test_cheating_dealer_who_stays_silent_is_disqualified(self):
        n, t = 5, 3
        parties = [Party(i, n, t) for i in range(1, n + 1)]
        parties[1].cheat_against = [4]      # party 2 sends a bad share to 4
        parties[1].refuse_to_reveal = True  # ...and ignores the complaint
        results = run_dkg(n, t, parties)
        for r in results:
            self.assertNotIn(2, r.qualified)
        self.assertEqual(len({r.group_public_key for r in results}), 1)
        x = reconstruct_secret({r.party_id: r.secret_share for r in results[:3]})
        self.assertEqual(g_pow(x), results[0].group_public_key)

    def test_dealer_who_reveals_a_bad_share_is_still_disqualified(self):
        n, t = 4, 2
        parties = [Party(i, n, t) for i in range(1, n + 1)]
        parties[0].cheat_against = [3]      # bad share; dealer reveals the same
        results = run_dkg(n, t, parties)    # bad share -> still fails the check
        self.assertNotIn(1, results[0].qualified)

    def test_falsely_accused_honest_dealer_survives_by_revealing(self):
        n, t = 5, 3
        parties = [Party(i, n, t) for i in range(1, n + 1)]
        parties[3].false_accuse = [1]       # party 4 lies about honest party 1
        results = run_dkg(n, t, parties)
        for r in results:
            self.assertIn(1, r.qualified)   # party 1 revealed a valid share
        x = reconstruct_secret({r.party_id: r.secret_share for r in results[2:]})
        self.assertEqual(g_pow(x), results[0].group_public_key)

    def test_save_and_load_round_trip(self):
        results = run_dkg(4, 2)
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "out.json")
            save_results(results, path)
            loaded = load_results(path)
        self.assertEqual([r.to_dict() for r in loaded], [r.to_dict() for r in results])

    def test_lagrange_weights_sum_to_one(self):
        idx = [1, 3, 5]
        self.assertEqual(sum(lagrange_coefficient(i, idx) for i in idx) % Q, 1)


if __name__ == "__main__":
    unittest.main()
