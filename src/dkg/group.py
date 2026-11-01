"""
group.py -- the shared maths "playing field" for the whole project.

PLAIN ENGLISH
-------------
Everything in DKG, threshold signing and handover happens inside one
mathematical group, exactly like the Diffie-Hellman / Schnorr setting from
Weeks 7 and 9:

    P  -- a big "safe" prime, P = 2*Q + 1
    Q  -- a big prime: the ORDER of the group. All secrets, shares and
          polynomial coefficients are numbers mod Q.
    G  -- a generator: G**x mod P is a "public key" for secret x.
          Going from x to G**x is easy; going back is the discrete-log
          problem, which is believed to be hard.

ALL FOUR TEAM MEMBERS MUST USE THESE SAME THREE NUMBERS.
Import them from here -- never retype them.

Note: 256-bit Q keeps the demo fast. A production system would use a
standard elliptic curve (e.g. secp256k1, which Bitcoin uses). The maths is
identical; only the group changes.
"""

import secrets

P = 0x14D551987D68A21236789812CAFE354085A6AE5A89AD48D7661A04BBE4AC7D6AF
Q = 0xA6AA8CC3EB451091B3C4C09657F1AA042D3572D44D6A46BB30D025DF2563EB57
G = 4


def random_scalar() -> int:
    """A uniformly random secret number in the range 1 .. Q-1."""
    return secrets.randbelow(Q - 1) + 1


def g_pow(x: int) -> int:
    """G**x mod P -- turns a secret number into its public 'key' form."""
    return pow(G, x % Q, P)


def _self_check() -> None:
    # G must have order exactly Q, otherwise every proof below breaks.
    assert pow(G, Q, P) == 1, "G does not have order Q"
    assert G != 1


_self_check()
