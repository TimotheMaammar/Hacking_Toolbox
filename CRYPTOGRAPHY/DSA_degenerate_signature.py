#!/usr/bin/env python3
"""
DSA / ElGamal degenerate-signature forgery.

USAGE
    When a DSA or ElGamal verifier (1) does not strictly require 0 < r < q and
    0 < s < q, and (2) uses a modular inverse that returns a falsy value (0, False,
    None) on failure instead of raising. Produces a universal forgery valid for any
    message without the private key.

HOW IT WORKS
    Picking s = 0 (or any multiple of q) makes w = inv(s) = 0, so u1 = H*w = 0 and
    u2 = r*w = 0, hence v = (g^0 * y^0 mod p) mod q = 1. The check v == r then passes
    for r = 1. Signature "1:0" (format r:s) is therefore valid for every message.

RUN
    Optionally provide q, then submit the printed signature as the signature for the
    target message.

NOTES
    - Try "1:0" first. If s = 0 is rejected before the verify step, try "1:q" or
      "1:2q" (also 0 mod q, same collapse).
    - Fix: reject r, s outside [1, q-1] and make modinv raise on non-invertible input.
"""

def forgeries(q=None):
    out = ["1:0"]                 # s = 0 -> inv fails -> v = 1 -> r must be 1
    if q is not None:
        out += [f"1:{q}", f"1:{2*q}"]   # s = q, 2q (= 0 mod q), same effect
    return out


if __name__ == "__main__":
    print(__doc__)
    q = input("q (optional, Enter to skip): ").strip()
    q = int(q) if q else None
    print("\nUniversal forgery signature(s) to submit (format r:s) for any message:")
    for sig in forgeries(q):
        print("   ", sig)
