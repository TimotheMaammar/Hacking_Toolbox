#!/usr/bin/env python3
"""
SQUARE (integral) attack on round-reduced AES-128.

USAGE
    When AES-128 is reduced to 4 rounds (last round without MixColumns) and a
    chosen-plaintext encryption oracle is available. Recovers the master key.

HOW IT WORKS
    A lambda set is 256 plaintexts where one byte takes all values and the other
    15 are constant. After 3 rounds the state is balanced (per byte, the XOR over
    the 256 texts is 0). The reduced 4th round is peeled byte by byte: the correct
    last-round-key byte is the one for which XOR of InvSBox(ct_byte ^ guess) over
    the set is 0. A few lambda sets pin all 16 bytes; the key schedule is then
    inverted to the master key.

RUN
    Enter the oracle host/port. A live oracle is required (256 encryptions per set,
    a few sets), so it drives the connection rather than pasting values. The example
    speaks `e <hexpt>` / `c <hexkey>`; adapt the oracle glue to the target.

NOTES
    - round_last is the index of the last round key (4-round AES -> 4); change it
      only if rounds are numbered differently.
    - Queries are batched per set; the loop stops once every byte is unique.
"""

import os
from functools import reduce

SBOX = bytes.fromhex(
 "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
 "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
 "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
 "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
 "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
 "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
 "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
 "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")
INV_SBOX = [0]*256
for _i, _v in enumerate(SBOX):
    INV_SBOX[_v] = _i

def _xtime(a):
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a
_RC = [0x00, 0x01]                       # key-schedule round constants
while len(_RC) < 32:
    _RC.append(_xtime(_RC[-1]))
_rotw = lambda w: w[1:] + w[:1]
_subw = lambda w: [SBOX[b] for b in w]
_xorw = lambda a, b: [x ^ y for x, y in zip(a, b)]


def invert_key_schedule(last_round_key, round_last=10):
    """Turn any round key back into the AES-128 master key (schedule is invertible)."""
    W = {}
    for j in range(4):
        W[4*round_last + j] = last_round_key[4*j:4*j + 4]
    for i in range(4*round_last + 3, 3, -1):
        t = _xorw(_subw(_rotw(W[i-1])), [_RC[i//4], 0, 0, 0]) if i % 4 == 0 else W[i-1]
        W[i-4] = _xorw(W[i], t)
    return sum((W[j] for j in range(4)), [])


def square_attack(encrypt, round_last=4, active_pos=0, max_sets=12, rng=None):
    """encrypt(pt16)->ct16 ; returns (master_key_bytes, last_round_key_bytes)."""
    rng = rng or (lambda n: os.urandom(n))
    cand = [set(range(256)) for _ in range(16)]
    for s in range(max_sets):
        base = bytearray(rng(16)); cts = []
        for v in range(256):
            base[active_pos] = v
            cts.append(encrypt(bytes(base)))
        for p in range(16):                           # keep guesses whose InvSBox XOR-sum is 0
            cand[p] &= {g for g in range(256)
                        if 0 == reduce(lambda a, ct: a ^ INV_SBOX[ct[p] ^ g], cts, 0)}
        print(f"[*] lambda-set {s+1}: candidates/byte = {[len(c) for c in cand]}", flush=True)
        if all(len(c) == 1 for c in cand):
            break
    else:
        if not all(len(c) == 1 for c in cand):
            raise RuntimeError("key not unique: increase max_sets")
    klast = bytes(next(iter(c)) for c in cand)
    return invert_key_schedule(klast, round_last), klast


if __name__ == "__main__":
    import socket, time
    from binascii import hexlify, unhexlify

    HOST = input("oracle host: ").strip()
    PORT = int(input("oracle port: ").strip())
    ROUND_LAST = int(input("round_last [4]: ").strip() or "4")

    s = socket.socket(); s.connect((HOST, PORT)); s.settimeout(10)
    time.sleep(0.4)
    try: s.recv(8192)                                 # eat banner
    except socket.timeout: pass

    def encrypt_batch(pts):                           # send all 'e <hex>' at once, read one hex line each
        s.sendall(b"".join(b"e " + hexlify(p) + b"\n" for p in pts))
        out = b""
        while out.count(b"\n") < len(pts):
            d = s.recv(1 << 20)
            if not d: break
            out += d
        lines = [l for l in out.split(b"\n") if len(l) >= 32]
        return [unhexlify(l[:32]) for l in lines[:len(pts)]]

    def attack(active_pos=0):                          # inline so a whole lambda set stays batched
        cand = [set(range(256)) for _ in range(16)]
        for sidx in range(12):
            base = bytearray(os.urandom(16))
            pts = []
            for v in range(256):
                base[active_pos] = v
                pts.append(bytes(base))
            cts = encrypt_batch(pts)
            for p in range(16):
                cand[p] &= {g for g in range(256)
                            if 0 == reduce(lambda a, ct: a ^ INV_SBOX[ct[p] ^ g], cts, 0)}
            print(f"[*] set {sidx+1}: {[len(c) for c in cand]}", flush=True)
            if all(len(c) == 1 for c in cand): break
        klast = bytes(next(iter(c)) for c in cand)
        return invert_key_schedule(klast, ROUND_LAST), klast

    master, klast = attack()
    print("[*] last round key:", klast.hex())
    print("[+] MASTER KEY    :", master.hex())
    s.sendall(b"c " + hexlify(master) + b"\n")        # submit the recovered key
    time.sleep(1.0)
    print(s.recv(4096).decode(errors="replace"))
