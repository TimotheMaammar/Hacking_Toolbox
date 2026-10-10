#!/usr/bin/env python3
"""
RSA Corrupted Private Key — Generic Solver
Recovers p, q from a corrupted OpenSSL text dump (openssl rsa -text)
where the HIGH bytes of privateExponent are zeroed but the LOW bytes intact.

Usage: python3 solve.py private.dump secret.dat 
"""

import re, math, sys

def parse_dump(path):
    with open(path, 'rb') as f:
        data = f.read()

    blocks = [(m.start(), m.end()) for m in re.finditer(rb'(?:[0-9a-f]{2}:)+[0-9a-f]{2}', data)]

    def read_block(b):
        return bytes(int(x, 16) for x in data[b[0]:b[1]].decode().split(':'))

    parsed = [read_block(b) for b in blocks]

    # --- Modulus (n) ---
    # Find total modulus size: count blocks until the gap containing
    # "publicExponent" label text, then the privateExponent null lines begin.
    # Heuristic: the first field ends when a large gap of non-hex data appears
    # between two blocks. We look for the gap containing "xp" (from "Exponent").
    n_end_idx = None
    for i in range(len(blocks) - 1):
        gap = data[blocks[i][1]:blocks[i+1][0]]
        # publicExponent label sits between modulus and d fields
        if b'x' in gap or b'p' in gap:
            n_end_idx = i
            break

    if n_end_idx is None:
        raise ValueError("Could not locate modulus/exponent boundary")

    n_bytes = b''.join(parsed[:n_end_idx+1])
    n = int.from_bytes(n_bytes, 'big')

    # --- publicExponent (e) ---
    # Standard: 65537. Extract from gap text if present.
    gap_text = data[blocks[n_end_idx][1]:blocks[n_end_idx+1][0]]
    e = 65537  # default
    # Look for "65537" or "0x10001" in the (partially corrupted) gap
    match = re.search(rb'6\x005\x005\x003\x007|1\x000\x000\x000\x001', gap_text)
    if not match:
        # Try reading it from the next small block (e is usually a 3-byte block: 01:00:01)
        next_blk = parsed[n_end_idx + 1]
        if len(next_blk) <= 4:
            e = int.from_bytes(next_blk, 'big')
            n_end_idx += 1  # skip the e block

    # --- d_low: all intact hex blocks after the modulus/e ---
    # These are the LOW bytes of privateExponent
    d_start_idx = n_end_idx + 1
    # Find where d ends: next large null gap (prime1 field starts)
    d_end_idx = None
    for i in range(d_start_idx, len(blocks) - 1):
        gap = data[blocks[i][1]:blocks[i+1][0]]
        # Large gap = new field label. If gap has a newline followed by mostly nulls → new field.
        null_lines = sum(1 for line in gap.split(b'\n') if line and all(b == 0 for b in line))
        if null_lines >= 2:
            d_end_idx = i
            break

    if d_end_idx is None:
        d_end_idx = len(blocks) - 1

    d_low_bytes = b''.join(parsed[d_start_idx:d_end_idx+1])
    d_low = int.from_bytes(d_low_bytes, 'big')
    M = len(d_low_bytes) * 8

    return n, e, d_low, M


def factor_n(n, e, d_low, M):
    """
    Recover p, q from n, e, and d mod 2^M.

    e·d = 1 + k·φ(n)  →  k·(p+q) ≡ 1 + k·(n+1) - e·d_low  (mod 2^M)

    If k is odd: p+q = k⁻¹ · RHS mod 2^M  (exact, since p+q < 2^M)
    If k = 2^s · k_odd: reduce modulus by s, check RHS divisible by 2^s.
    """
    mod = 2**M

    for k in range(1, e + 1):
        s = (k & -k).bit_length() - 1   # valuation v₂(k)
        k_odd = k >> s
        M_eff = M - s
        mod_eff = 2**M_eff

        RHS = (1 + k * ((n + 1) % mod) - (e * d_low) % mod) % mod

        if RHS % (2**s) != 0:
            continue

        RHS_r = RHS >> s
        t = pow(k_odd, -1, mod_eff) * RHS_r % mod_eff

        if t.bit_length() > M_eff - 10:
            continue   # p+q shouldn't fill the whole modulus

        disc = t * t - 4 * n
        if disc < 0:
            continue

        sq = math.isqrt(disc)
        if sq * sq != disc:
            continue

        p, q = (t + sq) // 2, (t - sq) // 2
        if p * q == n:
            return p, q

    return None, None


def decrypt(ct_path, n, e, p, q):
    with open(ct_path, 'rb') as f:
        ct = int.from_bytes(f.read(), 'big')

    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)
    m = pow(ct, d, n)
    m_bytes = m.to_bytes((m.bit_length() + 7) // 8, 'big')

    # PKCS#1 v1.5 unpad: 0x02 [padding] 0x00 [message]
    if m_bytes[0] == 0x02:
        sep = m_bytes.index(b'\x00', 1)
        return m_bytes[sep+1:]

    return m_bytes  # raw if no recognizable padding


if __name__ == '__main__':
    dump_path = sys.argv[1] if len(sys.argv) > 1 else 'private.dump'
    ct_path   = sys.argv[2] if len(sys.argv) > 2 else 'secret.dat'

    print(f"[*] Parsing {dump_path}...")
    n, e, d_low, M = parse_dump(dump_path)
    print(f"[*] n = {n.bit_length()} bits, e = {e}, d_low = {M} bits")

    print(f"[*] Factoring n (k ∈ [1, {e}])...")
    p, q = factor_n(n, e, d_low, M)

    if p is None:
        print("[-] Factoring failed.")
        sys.exit(1)

    print(f"[+] p = {hex(p)[:20]}...")
    print(f"[+] q = {hex(q)[:20]}...")

    plaintext = decrypt(ct_path, n, e, p, q)
    print(f"\n[+] Flag: {plaintext.decode('latin-1')}")
