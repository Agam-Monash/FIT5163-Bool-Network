"""FIT5163 Bool Network: threshold Schnorr signing over secp256k1.

Each Signer holds only its own secret share; Coordinator holds public shares.
Requires a trusted authenticated channel and DKG-verified public shares.
This is Schnorr implementation.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
from secrets import randbelow
from typing import Mapping, Sequence

"""
COMPONENT 1: SECP256K1 DOMAIN PARAMETERS
P is the curve field prime (point coordinates are reduced modulo P).
Q is the generator order (secret shares, nonce scalars and signatures use Q).
G is the standard secp256k1 generator. None represents the point at infinity.
CRITICAL INTEGRATION CONTRACT: DKG and handover must use this same curve, Q,
and compatible Shamir evaluation IDs; otherwise signature verification fails.
"""
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
Q = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
Point = tuple[int,int] | None


"""
COMPONENT 2: INPUT VALIDATION
Fail early on malformed parameters instead of continuing cryptographic work.
"""
def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)

"""
Check whether a value is a valid affine secp256k1 point (or infinity).
This is a mathematical curve-membership check, not authentication.
"""
def _on_curve(p: Point) -> bool:
    return p is None or (isinstance(p, tuple) and len(p)==2 and all(type(v) is int for v in p)
                          and 0 <= p[0] < P and 0 <= p[1] < P and p[1] * p[1] % P == (p[0]**3+7) % P)


"""
COMPONENT 3: ELLIPTIC-CURVE POINT ARITHMETIC
Add two curve points; None acts as the additive identity.
The slope differs between point doubling (a == b) and distinct points.
"""
def add(a: Point, b: Point) -> Point:
    _require(_on_curve(a) and _on_curve(b), "invalid curve point")
    if a is None: return b
    if b is None: return a
    x1,y1=a; x2,y2=b
    if x1==x2 and (y1+y2)%P==0: return None
    if a==b:
        lam=(3*x1*x1 * pow(2*y1, -1, P)) % P
    else:
        lam=((y2-y1)*pow((x2-x1)%P, -1, P))%P
    x3=(lam*lam-x1-x2)%P
    return (x3,(lam*(x1-x3)-y1)%P)


"""
Compute scalar multiplication k * p using binary double-and-add.
IMPORTANT: variable-time Python math is for academic demonstration, not for
production systems where timing side channels may reveal secret scalars.
"""
def mul(k: int, p: Point=G) -> Point:
    _require(type(k) is int and 0 <= k < Q, "scalar out of range")
    _require(_on_curve(p), "invalid curve point")
    out=None
    while k:
        if k & 1: out=add(out,p)
        p=add(p,p)
        k >>= 1
    return out


"""
Encode a non-identity point as SEC1 compressed bytes (33 bytes):
0x02/0x03 indicates y parity; the remaining 32 bytes store x.
"""
def encode_point(p: Point) -> bytes:
    _require(p is not None and _on_curve(p), "identity or invalid point")
    return (b'\x02' if p[1]%2==0 else b'\x03') + p[0].to_bytes(32,'big')


"""
Decode SEC1 compressed point bytes and recover y from the curve equation.
Reject noncanonical x coordinates and values that do not lie on the curve.
"""
def decode_point(data: bytes) -> Point:
    _require(isinstance(data,bytes) and len(data)==33 and data[0] in (2,3), "invalid compressed point encoding")
    x=int.from_bytes(data[1:],'big')
    _require(x<P, "point x coordinate out of range")
    y=pow((x*x*x+7)%P,(P+1)//4,P)
    if y%2 != data[0]%2: y=P-y
    p=(x,y)
    _require(_on_curve(p), "point is not on the curve")
    return p

"""
COMPONENT 4: SESSION TRANSCRIPT AND INTERPOLATION HELPERS
Domain-separated SHA-256 -> scalar modulo Q. Length-prefixing the chunks
avoids ambiguous concatenations between different hash input fields.
"""
def _hash(tag: bytes, *chunks: bytes) -> int:
    h=sha256(b'FIT5163-THRESHOLD-SCHNORR-V1/'+tag)
    for chunk in chunks:
        h.update(len(chunk).to_bytes(8,'big'));h.update(chunk)
    return int.from_bytes(h.digest(),'big')%Q


"""
Canonicalise signer IDs for deterministic interpolation/transcripts; require
unique positive Shamir evaluation indices and at least threshold signers.
"""
def _ids(ids: Sequence[int], threshold: int) -> tuple[int,...]:
    result=tuple(sorted(ids))
    _require(type(threshold) is int and threshold>=2, "threshold must be at least 2")
    _require(len(result)>=threshold and len(set(result))==len(result), "insufficient or duplicate participants")
    _require(all(type(i) is int and 1<=i<Q for i in result), "invalid participant ID")
    return result


"""
Compute interpolation coefficient at x=0 for a selected signer i:
lambda_i = PRODUCT_{j != i} (-j)/(i-j) modulo Q.
These weights allow secret shares to contribute to signatures for the
original group public key without reconstructing the group private key.
"""
def lagrange(i: int, ids: Sequence[int]) -> int:
    _require(i in ids and len(set(ids))==len(ids), "invalid interpolation participants")
    numerator=denominator=1
    for j in ids:
        if j!=i:
            numerator=numerator*(-j)%Q
            denominator=denominator*(i-j)%Q
    return numerator*pow(denominator%Q,-1,Q)%Q

"""
COMPONENT 5: PUBLIC PROTOCOL MESSAGE TYPES
Immutable value containers passed between signer and coordinator.
These store public protocol data, NOT the private nonce scalars or shares.
"""
@dataclass(frozen=True)
class NonceCommitment:
    member_id: int
    hiding: bytes
    binding: bytes


"""
Coordinator-to-signers context: message, unique session, active members,
their nonce commitments, common group public key and signing threshold.
"""
@dataclass(frozen=True)
class SigningPackage:
    session_id: bytes
    message: bytes
    commitments: tuple[NonceCommitment,...]
    group_public_key: bytes
    threshold: int


"""
Signer-to-coordinator response: member ID plus its scalar contribution z_i.
"""
@dataclass(frozen=True)
class PartialSignature:
    member_id: int
    z: int


"""
Final Schnorr-style group signature: aggregate nonce point R and scalar z.
The custom 65-byte encoding is NOT a Bitcoin/Ethereum ECDSA signature.
"""
@dataclass(frozen=True)
class Signature:
    R: bytes
    z: int
    def to_bytes(self)->bytes:
        return self.R + self.z.to_bytes(32,'big')
    @classmethod
    def from_bytes(cls,data:bytes)->'Signature':
        _require(isinstance(data,bytes) and len(data)==65, "expected 65-byte signature")
        return cls(data[:33],int.from_bytes(data[33:],'big'))

"""
COMPONENT 6: SIGNING-ROUND PUBLIC CALCULATIONS
Construct the public signing transcript used for nonce-binding factors.
Includes the session ID, participant commitments, public key, message,
and threshold, making factors specific to this signing session.
"""
def _package_data(pkg:SigningPackage) -> bytes:
    return (pkg.session_id + b''.join(c.member_id.to_bytes(32,'big')+c.hiding+c.binding for c in pkg.commitments)
            +pkg.group_public_key+pkg.message+pkg.threshold.to_bytes(4,'big'))


"""
Derive per-member rho_i values tied to the entire public transcript.
Factors prevent freely mixing signer nonce commitments across contexts.
"""
def _binding_factors(pkg:SigningPackage)->dict[int,int]:
    transcript=_package_data(pkg)
    return {c.member_id:_hash(b'binding',transcript,c.member_id.to_bytes(32,'big')) for c in pkg.commitments}


"""
Combine each signer's public nonce points: R_i = D_i + rho_i * E_i;
sum R_i to obtain the group nonce R. Abort if the sum is the identity.
"""
def _commitment_points(pkg:SigningPackage)->tuple[Point,dict[int,Point]]:
    factors=_binding_factors(pkg)
    individual={}
    aggregate=None
    for c in pkg.commitments:
        individual[c.member_id]=add(decode_point(c.hiding),mul(factors[c.member_id],decode_point(c.binding)))
        aggregate=add(aggregate,individual[c.member_id])
    _require(aggregate is not None, "aggregate nonce is identity; abort and restart")
    return aggregate,individual


"""
Generate Schnorr challenge c = H(R, group_public_key, message).
Both signing and verification MUST calculate this challenge identically.
"""
def _challenge(pkg:SigningPackage, aggregate:Point)->int:
    return _hash(b'challenge',encode_point(aggregate),pkg.group_public_key,pkg.message)

"""
COMPONENT 7: COORDINATED SIGNING PACKAGE CONSTRUCTION
Validate and sort all public commitments before distributing the shared
session package. This version requires EXACTLY threshold active signers.
"""
def make_package(session_id:bytes,message:bytes,commitments:Sequence[NonceCommitment],
                 group_public_key:bytes,threshold:int)->SigningPackage:
    _require(isinstance(session_id,bytes) and len(session_id)>=16,"session ID must be >=16 bytes")
    _require(isinstance(message,bytes),"message must be bytes")
    ordered=tuple(sorted(commitments,key=lambda c:c.member_id))
    _ids([c.member_id for c in ordered],threshold)
    _require(len(ordered)==threshold,"exactly threshold signers required in this implementation")
    _require(decode_point(group_public_key) is not None,"invalid public key")
    for c in ordered: decode_point(c.hiding);decode_point(c.binding)
    pkg=SigningPackage(session_id,message,ordered,group_public_key,threshold)
    _commitment_points(pkg)
    return pkg


"""
COMPONENT 8: PARTICIPANT-SIDE TWO-ROUND THRESHOLD SIGNING
Each Signer owns ONE private DKG/handover share. Do not transmit _share or
_pending to the Coordinator. A real deployment would isolate each signer
in a separate process/device with authenticated communication.
"""
class Signer:
    """One committee member. Keep instances and their secret shares isolated.

    DKG shares are Shamir f(member_id) modulo secp256k1 order Q.
    No secret material is returned by any public method.
    """
    """
    Initialise the participant and derive its PUBLIC verification share.
    Pending stores (private nonce d, private nonce e, public commitment)
    indexed by session ID; used tracks spent sessions to block nonce reuse.
    """
    def __init__(self,member_id:int,secret_share:int):
        _require(type(member_id) is int and 1<=member_id<Q,"invalid member ID")
        _require(type(secret_share) is int and 0<=secret_share<Q,"invalid secret share")
        self.member_id=member_id
        self._share=secret_share
        self.public_share=encode_point(mul(secret_share)) if secret_share else None
        self._pending:dict[bytes,tuple[int,int,NonceCommitment]]={}
        self._used:set[bytes]=set()

    """
    ROUND 1: create fresh secret nonce scalars (d,e), publish only D=dG and
    E=eG, and retain private nonces locally for the matching session.
    """
    def commit(self,session_id:bytes)->NonceCommitment:
        _require(isinstance(session_id,bytes) and len(session_id)>=16,"session ID must be >=16 bytes")
        _require(session_id not in self._pending and session_id not in self._used,"reused session ID")
        d=1+randbelow(Q-1);e=1+randbelow(Q-1)
        c=NonceCommitment(self.member_id,encode_point(mul(d)),encode_point(mul(e)))
        self._pending[session_id]=(d,e,c)
        return c

    """
    ROUND 2: consume the stored nonces ONCE; verify own published commitment
    is present, compute rho, lambda, c, and return the partial signature:
    z_i = d_i + rho_i * e_i + lambda_i * share_i * c  (mod Q).
    Consuming nonces before package validation avoids accidentally reusing
    them after a failed attempt; callers should start with a new session.
    """
    def sign(self,pkg:SigningPackage)->PartialSignature:
        _require(pkg.session_id in self._pending,"no fresh nonce for session")
        d,e,commitment=self._pending.pop(pkg.session_id)
        self._used.add(pkg.session_id)  # burn nonces even if validation fails
        _require(any(c==commitment for c in pkg.commitments),"own commitment missing or changed")
        ids=[c.member_id for c in pkg.commitments]
        _require(self.member_id in ids,"participant not selected")
        aggregate,_=_commitment_points(pkg)
        rho=_binding_factors(pkg)[self.member_id]
        challenge=_challenge(pkg,aggregate)
        z=(d+rho*e+lagrange(self.member_id,ids)*self._share*challenge)%Q
        return PartialSignature(self.member_id,z)

"""
COMPONENT 9: COORDINATOR-SIDE PUBLIC VERIFICATION AND AGGREGATION
Holds a mapping member_id -> public verification share and the group key.
It should NOT receive the participants' private shares or nonce scalars.
"""
class Coordinator:
    """Coordinator sees public shares and commitments, never secret shares."""
    """
    Configure the committee verification context supplied by DKG/handover.
    Public shares must be authentic and consistent with the group key;
    this constructor checks encodings, not the DKG security proof.
    """
    def __init__(self,group_public_key:bytes,public_shares:Mapping[int,bytes],threshold:int):
        self.group_public_key=group_public_key
        decode_point(group_public_key)
        _require(type(threshold) is int and threshold>=2,"invalid threshold")
        self.threshold=threshold
        self.public_shares=dict(public_shares)
        for member_id,public_share in self.public_shares.items():
            _require(type(member_id) is int and 1<=member_id<Q,"invalid member ID")
            decode_point(public_share)

    """
    Assemble a shared signing package from the selected signers' public
    nonce commitments. Reject unknown committee member IDs.
    """
    def package(self,session_id:bytes,message:bytes,commitments:Sequence[NonceCommitment])->SigningPackage:
        pkg=make_package(session_id,message,commitments,self.group_public_key,self.threshold)
        _require(all(c.member_id in self.public_shares for c in pkg.commitments),"unknown member")
        return pkg

    """
    Verify all partial signatures using public shares, then add their z_i.
    Check: z_i*G == R_i + c*lambda_i*Y_i for each member.
    Final signature: (R, sum(z_i) mod Q), independently verified below.
    """
    def aggregate(self,pkg:SigningPackage,partials:Sequence[PartialSignature])->Signature:
        _require(pkg.group_public_key==self.group_public_key and pkg.threshold==self.threshold,"incompatible package")
        ids=[c.member_id for c in pkg.commitments]
        _require(len(partials)==len(ids) and set(p.member_id for p in partials)==set(ids),"missing or duplicate partial signatures")
        aggregate,individual=_commitment_points(pkg)
        e=_challenge(pkg,aggregate)
        for partial in partials:
            _require(type(partial.z) is int and 0<=partial.z<Q,"malformed partial signature")
            public=decode_point(self.public_shares[partial.member_id])
            right=add(individual[partial.member_id],mul(e*lagrange(partial.member_id,ids)%Q,public))
            _require(mul(partial.z)==right,f"invalid signature share from member {partial.member_id}")
        signature=Signature(encode_point(aggregate),sum(p.z for p in partials)%Q)
        _require(verify(pkg.message,signature,self.group_public_key),"aggregated signature is invalid; shares/key may be incompatible")
        return signature


"""
COMPONENT 10: FINAL SIGNATURE VERIFICATION
Verify z*G == R + H(R, group_public_key, message)*group_public_key.
This checks cryptographic consistency, not the business validity of a
blockchain transaction. Invalid data returns False instead of crashing.
"""
def verify(message:bytes,signature:Signature,group_public_key:bytes)->bool:
    try:
        if not isinstance(message,bytes) or not isinstance(signature,Signature):return False
        if type(signature.z) is not int or not 0<=signature.z<Q:return False
        R=decode_point(signature.R);Y=decode_point(group_public_key)
        e=_hash(b'challenge',signature.R,group_public_key,message)
        return mul(signature.z)==add(R,mul(e,Y))
    except (ValueError,TypeError,OverflowError):return False

"""
Test

Create a random Shamir polynomial with constant term `secret`. Its sampled
shares and corresponding public points let this module be demoed alone.
"""
def _demo_dkg_fixture(secret:int,threshold:int,count:int)->tuple[bytes,dict[int,int],dict[int,bytes]]:
    """Only for tests/demo; actual DKG MUST replace this fixture."""
    _require(2<=threshold<=count<Q and 1<=secret<Q,"invalid fixture")
    coefficients=[secret]+[randbelow(Q) for _ in range(threshold-1)]
    shares={i:sum(coef*pow(i,power,Q) for power,coef in enumerate(coefficients))%Q for i in range(1,count+1)}
    return encode_point(mul(secret)),shares,{i:encode_point(mul(value)) for i,value in shares.items() if value}


"""
Demonstrates a 3-of-5 committee: choose members 1,3,5; commit nonces;
assemble one package; sign individually; aggregate; verify a valid message
and show that changing the message invalidates the original signature.
"""
def demo()->None:
    from secrets import token_bytes
    group_key, shares, public_shares=_demo_dkg_fixture(123456789,3,5)
    signers=[Signer(i,shares[i]) for i in (1,3,5)]
    coordinator=Coordinator(group_key,public_shares,3)
    sid=token_bytes(32);message=b'Bool Network committee transaction: test only'
    commitments=[s.commit(sid) for s in signers]
    pkg=coordinator.package(sid,message,commitments)
    partials=[s.sign(pkg) for s in signers]
    signature=coordinator.aggregate(pkg,partials)
    print('threshold: 3-of-5; active members: 1,3,5')
    print('group public key:',group_key.hex())
    print('signature:',signature.to_bytes().hex())
    print('valid message:',verify(message,signature,group_key))
    print('tampered message:',verify(message+b'!',signature,group_key))

"""
Only run the example when invoked directly; importing this file does not
automatically initiate signing or generate shares.
"""
if __name__=='__main__':demo()