#!/usr/bin/env python3
"""
ECDSA nonce reuse key recovery.

This is the classic ECDSA implementation bug: if the per-signature random
nonce k is ever reused across two signatures, the private key falls out of
basic algebra. It is not just a CTF trick, it is how Sony's PS3 signing key
was recovered in 2010 (a constant k instead of a random one).

USAGE
    A set of ECDSA signatures (same key) is available, and at least two of
    them are suspected or confirmed to share the same r value (same nonce).
    Recovers the private key, then can sign an arbitrary message with it.

HOW IT WORKS
    r only depends on k, not on the message, so two signatures with equal r
    very likely used the same k. From
        s1 = k^-1 (h1 + r*d) mod n
        s2 = k^-1 (h2 + r*d) mod n
    subtracting gives k, then d, independent of which hash function or
    encoding produced h1/h2. The correct hash function is identified
    automatically by recomputing d*G and comparing it to the known public
    key, no need to guess it ahead of time.

RUN
    Give find_reused_r a list of {"text": ..., "r": ..., "s": ...} (from
    parse_der_signature on your captured signatures). Feed the pair that
    shares r, plus the curve and public key point, to auto_recover_key. Then
    sign_message with the recovered d for whatever the target asks you to
    sign.

NOTES
    - r collisions are necessary but not sufficient evidence: with enough
      signatures a coincidental match is possible for small curves, though
      astronomically unlikely for standard NIST curves (n ~2^256+). Always
      confirm by re-deriving the public key from the recovered d.
    - The hash function is tried from a short common list (SHA-1/256/384/512,
      SHA3 variants, MD5) with FIPS 186-4 truncation to the curve's bit
      length; add to the list if none of them match.
    - Needs the `ecdsa` package (pure Python, pip install ecdsa).
"""

import base64
import hashlib
from collections import defaultdict

from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigdecode_der, sigencode_der


def load_public_key(pem_bytes):
    """Returns (VerifyingKey, curve)."""
    vk = VerifyingKey.from_pem(pem_bytes)
    return vk, vk.curve


def parse_der_signature(sig_b64_or_der, curve):
    """Decode a base64 or raw DER ECDSA signature into (r, s)."""
    der = base64.b64decode(sig_b64_or_der) if isinstance(sig_b64_or_der, str) else sig_b64_or_der
    return sigdecode_der(der, curve.order)


def find_reused_r(signed_messages):
    """signed_messages: list of dicts with at least 'r' (int). Returns a dict
    {r: [messages]} containing only r values that appear more than once."""
    by_r = defaultdict(list)
    for m in signed_messages:
        by_r[m["r"]].append(m)
    return {r: v for r, v in by_r.items() if len(v) > 1}


def _hash_to_int(message_bytes, hashfunc, n_bitlen):
    """FIPS 186-4 style: leftmost n_bitlen bits of the hash digest, as int."""
    digest = hashfunc(message_bytes).digest()
    z = int.from_bytes(digest, "big")
    dbits = len(digest) * 8
    if dbits > n_bitlen:
        z >>= (dbits - n_bitlen)
    return z


HASH_CANDIDATES = {
    "sha1": hashlib.sha1, "sha256": hashlib.sha256, "sha384": hashlib.sha384,
    "sha512": hashlib.sha512, "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384, "sha3_512": hashlib.sha3_512, "md5": hashlib.md5,
}


def recover_private_key(curve, r, s1, h1, s2, h2):
    """Given two signatures sharing r (same nonce k), with message hashes
    already reduced to ints (h1 != h2), returns (d, k)."""
    n = curve.order
    denom = (s1 - s2) % n
    k = ((h1 - h2) * pow(denom, -1, n)) % n
    d = ((s1 * k - h1) * pow(r, -1, n)) % n
    return d, k


def auto_recover_key(curve, public_key, m1, m2, hash_candidates=None):
    """m1, m2: dicts with 'text' (str, the signed message), 'r', 's' (same r).
    Tries each candidate hash function, keeps the one whose recovered d
    reproduces the known public key. Returns (d, hash_name) or raises
    RuntimeError if none match."""
    hash_candidates = hash_candidates or HASH_CANDIDATES
    n_bitlen = curve.order.bit_length()
    r = m1["r"]
    if m2["r"] != r:
        raise ValueError("m1 and m2 do not share the same r; they were not signed with the same nonce")
    for name, hf in hash_candidates.items():
        h1 = _hash_to_int(m1["text"].encode(), hf, n_bitlen)
        h2 = _hash_to_int(m2["text"].encode(), hf, n_bitlen)
        if h1 == h2 or (m1["s"] - m2["s"]) % curve.order == 0:
            continue
        d, k = recover_private_key(curve, r, m1["s"], h1, m2["s"], h2)
        candidate_point = d * curve.generator
        if candidate_point == public_key.pubkey.point:
            return d, name
    raise RuntimeError("no hash function in the candidate list reproduced the public key")


def sign_message(curve, d, message, hashfunc=hashlib.sha256):
    """Returns the base64 DER signature for `message` (str) under private
    scalar d, ready to submit wherever a signature is expected."""
    sk = SigningKey.from_secret_exponent(d, curve=curve, hashfunc=hashfunc)
    der = sk.sign(message.encode(), hashfunc=hashfunc, sigencode=sigencode_der)
    return base64.b64encode(der).decode()


# =============================================================================
# Example: a folder of "message\nsignature_b64\n" files + a PEM public key.
# =============================================================================
if __name__ == "__main__":
    import glob
    import os

    PUBKEY_PEM = ""   # <-- path to public.pem
    MSG_GLOB = ""     # <-- e.g. r"messages/m*"
    TARGET_TEXT = ""  # <-- message the service asks you to sign, once d is found

    if not PUBKEY_PEM or not MSG_GLOB:
        raise SystemExit("set PUBKEY_PEM and MSG_GLOB before running")

    with open(PUBKEY_PEM, "rb") as f:
        vk, curve = load_public_key(f.read())
    print("curve:", curve.name)

    signed = []
    for path in sorted(glob.glob(MSG_GLOB)):
        with open(path) as f:
            text, sig_b64 = f.read().splitlines()[:2]
        r, s = parse_der_signature(sig_b64.strip(), curve)
        signed.append({"file": os.path.basename(path), "text": text, "r": r, "s": s})

    reused = find_reused_r(signed)
    print(f"{len(signed)} signatures, {len(reused)} reused r value(s)")
    if not reused:
        raise SystemExit("no nonce reuse found; this attack does not apply directly")

    r, group = next(iter(reused.items()))
    print("reused r in:", [m["file"] for m in group])
    d, hash_name = auto_recover_key(curve, vk, group[0], group[1])
    print(f"recovered private key (hash={hash_name}): {hex(d)}")

    if TARGET_TEXT:
        sig = sign_message(curve, d, TARGET_TEXT)
        print("signature for target message:", sig)
