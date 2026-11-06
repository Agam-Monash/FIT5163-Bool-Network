"""python -m unittest -v test_integration     (about 1-2 minutes: pure-Python EC maths)"""
import secrets
import unittest

from bool_net import dkg, handover as ho, ring_vrf
from bool_net.board import Board
from bool_net.curve import G, Q, enc, rand_scalar, reconstruct, smul
from bool_net.epoch import Network
from bool_net.hybrid import prove_dh
from bool_net.sortition import try_win, verify_winner
from bool_net.threshold_signing import Coordinator, Signer, verify


def sign_with(results, seats, msg=b"integration test"):
    r0 = results[0]
    coord = Coordinator(enc(r0.group_public_key), {k: enc(v) for k, v in r0.public_shares.items()}, r0.threshold)
    by_id = {r.party_id: r for r in results}
    signers = [Signer(s, by_id[s].secret_share) for s in seats]
    sid = secrets.token_bytes(32)
    pkg = coord.package(sid, msg, [s.commit(sid) for s in signers])
    sig = coord.aggregate(pkg, [s.sign(pkg) for s in signers])
    return verify(msg, sig, enc(r0.group_public_key))


def make_new_committee(c2, t1, t2, ctx):
    esks = {k: rand_scalar() for k in range(1, c2 + 1)}
    return esks, [ho.NewMember(k, t1, t2, esks[k], ctx) for k in esks]


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.old = dkg.run_dkg(4, 3)               # shared 3-of-4 committee for handover tests
        cls.gpk = cls.old[0].group_public_key
        cls.ppk = cls.old[0].public_shares
        cls.ctx = b"test-handover"

    def old_members(self, new, t2, c2, cheat=None):
        epks = {m.idx: m.epk for m in new}
        cheat = cheat or {}
        return [ho.OldMember(r.party_id, r.secret_share, t2, c2, epks, self.ctx,
                             cheat_against=cheat.get(r.party_id, set())) for r in self.old]

    def test_all_modules_share_one_group(self):
        self.assertEqual(ring_vrf.G, G)
        self.assertEqual(ring_vrf.N, Q)

    def test_dkg_output_signs(self):
        self.assertTrue(sign_with(self.old, [1, 3, 4]))

    def test_dkg_cheater_disqualified(self):
        parties = [dkg.Party(i, 4, 3) for i in range(1, 5)]
        parties[1].cheat_against, parties[1].refuse_to_reveal = [3], True
        res = dkg.run_dkg(4, 3, parties)
        self.assertEqual(res[0].qualified, [1, 3, 4])

    def test_handover_preserves_key_and_signs(self):
        _, new = make_new_committee(5, 3, 3, self.ctx)
        res, rep = ho.run_handover(self.old_members(new, 3, 5), new, self.ppk, self.gpk, self.ctx)
        self.assertFalse(rep.disqualified)
        self.assertTrue(all(r.group_public_key == self.gpk for r in res))
        self.assertTrue(sign_with(res, [2, 4, 5]))
        old_secret = reconstruct({r.party_id: r.secret_share for r in self.old[:3]})
        new_secret = reconstruct({r.party_id: r.secret_share for r in res[:3]})
        self.assertEqual(old_secret, new_secret)

    def test_handover_can_change_threshold_and_size(self):
        _, new = make_new_committee(6, 3, 4, self.ctx)
        res, _ = ho.run_handover(self.old_members(new, 4, 6), new, self.ppk, self.gpk, self.ctx)
        self.assertTrue(sign_with(res, [1, 2, 5, 6]))

    def test_cheating_dealer_is_disqualified_and_handover_still_completes(self):
        _, new = make_new_committee(4, 3, 3, self.ctx)
        old = self.old_members(new, 3, 4, cheat={2: {1}})
        res, rep = ho.run_handover(old, new, self.ppk, self.gpk, self.ctx)
        self.assertEqual(rep.disqualified, {2})
        self.assertTrue(sign_with(res, [1, 2, 3]))

    def test_false_accusation_does_not_disqualify_honest_dealer(self):
        _, new = make_new_committee(4, 3, 3, self.ctx)
        new[0].false_complaint_against = {1}      # seat 1 lies about dealer 1
        res, rep = ho.run_handover(self.old_members(new, 3, 4), new, self.ppk, self.gpk, self.ctx)
        self.assertEqual(rep.disqualified, set())
        self.assertEqual(rep.bad_complainers, {1})

    def test_forged_complaint_proof_is_rejected(self):
        esks, new = make_new_committee(4, 3, 3, self.ctx)
        msgs = {o.idx: o.deal() for o in self.old_members(new, 3, 4)}
        k, j = 2, 1
        R = msgs[j].cts[k]["R"]
        fakeS = smul(7)
        complaint = {"by": k, "against": j, "S": fakeS, "proof": prove_dh(esks[k], R, new[k - 1].epk, fakeS)}
        bad_d, bad_c = ho.adjudicate(msgs, [complaint], self.ppk, {m.idx: m.epk for m in new}, self.ctx, 3, 4)
        self.assertEqual((bad_d, bad_c), (set(), {k}))

    def test_ring_vrf_proof_is_bound_to_epk(self):
        keys = [ring_vrf.RingVRF.generate_keypair() for _ in range(4)]
        registry = {pk for _, pk in keys}
        rv, ring, seed, T = ring_vrf.RingVRF(keys[0][0]), [pk for _, pk in keys], b"seed", 1 << 256
        payload, _ = try_win(rv, seed, ring, T)
        self.assertTrue(verify_winner(payload, seed, T, registry))
        stolen = dict(payload, epk=ring_vrf.RingVRF.generate_keypair()[1])   # copy proof, swap in my epk
        self.assertFalse(verify_winner(stolen, seed, T, registry))
        self.assertFalse(verify_winner(dict(payload, vrf_hash=b"\x00" * 32), seed, T, registry))
        self.assertFalse(verify_winner(payload, seed, T, registry - {ring[1]}))   # ring member not registered

    def test_invalid_parameters_are_rejected_with_clear_errors(self):
        with self.assertRaises(ValueError):
            dkg.run_dkg(3, 5)                      # t > n
        with self.assertRaises(ValueError):
            dkg.run_dkg(4, 1)                      # t < 2
        with self.assertRaises(ValueError):
            Network(num_nodes=5, ring_size=6)      # ring larger than population
        with self.assertRaises(ValueError):
            Network(num_nodes=8, min_size=6, max_size=4)
        with self.assertRaises(ValueError):
            Network(num_nodes=8, win_fraction=(0, 4))
        _, new = make_new_committee(4, 3, 9, self.ctx)      # t2 > c2
        with self.assertRaises(ValueError):
            ho.run_handover(self.old_members(new, 9, 4), new, self.ppk, self.gpk, self.ctx)
        _, new = make_new_committee(4, 3, 3, self.ctx)
        with self.assertRaises(RuntimeError):               # too few honest dealers left
            ho.run_handover(self.old_members(new, 3, 4, cheat={1: {1}, 2: {1}}), new, self.ppk, self.gpk, self.ctx)
        self.assertFalse(verify_winner({}, b'seed', 1 << 256, set()))   # malformed payload -> False, no crash

    def test_full_epochs_through_orchestrator(self):
        from bool_net.epoch import sign
        net = Network(num_nodes=8, ring_size=3, min_size=4, max_size=5)
        c0 = net.advance()
        gpk = c0.gpk
        old_members = list(c0.members.values())
        for _ in range(2):
            c = net.advance()
            self.assertEqual(c.gpk, gpk)
            msg = b"epoch msg %d" % c.epoch
            self.assertTrue(verify(msg, sign(c, msg), enc(gpk)))
        self.assertTrue(all(m.share is None and m.esk is None for m in old_members))   # erased


if __name__ == "__main__":
    unittest.main()
