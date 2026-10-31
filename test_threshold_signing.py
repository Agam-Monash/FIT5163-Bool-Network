import secrets
import unittest
from dataclasses import replace
from threshold_signing import (Q,Signer,Coordinator,PartialSignature,Signature,verify,add,mul,
                                decode_point,encode_point,lagrange,_demo_dkg_fixture)

class SigningTests(unittest.TestCase):
    def setUp(self):
        self.key,self.shares,self.publics=_demo_dkg_fixture(15431,3,5)
        self.coordinator=Coordinator(self.key,self.publics,3)
        self.members=[Signer(i,self.shares[i]) for i in (1,3,5)]
        self.message=b'BTC lock -> wrapped token issue'
        self.sid=secrets.token_bytes(32)

    def round(self):
        pkg=self.coordinator.package(self.sid,self.message,[s.commit(self.sid) for s in self.members])
        partials=[s.sign(pkg) for s in self.members]
        return pkg,partials

    def test_valid(self):
        pkg,partials=self.round()
        sig=self.coordinator.aggregate(pkg,partials)
        self.assertTrue(verify(self.message,sig,self.key))
        self.assertEqual(Signature.from_bytes(sig.to_bytes()),sig)
        self.assertFalse(verify(self.message+b'bad',sig,self.key))

    def test_bad_partial(self):
        pkg,partials=self.round()
        partials[0]=replace(partials[0],z=(partials[0].z+1)%Q)
        with self.assertRaisesRegex(ValueError,'invalid signature share'):
            self.coordinator.aggregate(pkg,partials)

    def test_replay_and_nonce_reuse(self):
        pkg,_=self.round()
        with self.assertRaisesRegex(ValueError,'no fresh nonce'):
            self.members[0].sign(pkg)
        with self.assertRaisesRegex(ValueError,'reused session'):
            self.members[0].commit(self.sid)

    def test_missing_signer(self):
        with self.assertRaises(ValueError):
            self.coordinator.package(self.sid,self.message,[s.commit(self.sid) for s in self.members[:2]])

    def test_wrong_key(self):
        pkg,partials=self.round()
        bad_key=encode_point(mul(5))
        other=Coordinator(bad_key,self.publics,3)
        with self.assertRaises(ValueError):
            other.aggregate(pkg,partials)

    def test_bad_group_shares(self):
        pkg,partials=self.round()
        publics=dict(self.publics)
        publics[1]=encode_point(mul(123456))
        other=Coordinator(self.key,publics,3)
        with self.assertRaisesRegex(ValueError,'invalid signature share'):
            other.aggregate(pkg,partials)

    def test_shares_different_committee(self):
        # An independent degree-2 sharing of the same secret is a handover-like fixture.
        new_key,new_shares,new_publics=_demo_dkg_fixture(15431,3,5)
        self.assertEqual(new_key,self.key)
        new_members=[Signer(i,new_shares[i]) for i in (2,4,5)]
        other=Coordinator(self.key,new_publics,3)
        sid=secrets.token_bytes(32)
        pkg=other.package(sid,self.message,[s.commit(sid) for s in new_members])
        sig=other.aggregate(pkg,[s.sign(pkg) for s in new_members])
        self.assertTrue(verify(self.message,sig,self.key))

    def test_point_encoding(self):
        self.assertEqual(decode_point(encode_point(mul(123))),mul(123))
        with self.assertRaises(ValueError):decode_point(b'\x02'+b'\xff'*32)

if __name__=='__main__':unittest.main()
