#!/usr/bin/env python3
"""
Piret-Quisquater differential fault analysis (DFA) on AES-128.

USAGE
    When you have a correct ciphertext plus faulty ciphertexts of the same
    plaintext, each from a single-byte fault injected before the last MixColumns.
    Recovers the master key.

HOW IT WORKS
    A single-byte fault before the last MixColumns spreads to one column (4 bytes);
    the final round (no MixColumns) maps those to 4 ciphertext bytes forming one
    diagonal. For that diagonal, the 4 last-round-key bytes are the ones making the
    implied input difference equal to MixColumns of a single active byte. One fault
    per column recovers the whole last round key, then the key schedule is inverted.

RUN
    Paste the correct ciphertext then the faulty ones. Fully offline once the
    ciphertexts are gathered.

NOTES
    - The faulted row and the fault value are brute-forced (all rows, values 1..255),
      so multi-bit faults also work and the exact faulted byte need not be known; the
      affected diagonal is detected automatically.
    - round_last = 10 for standard AES-128.
    - One usable fault per column is enough; if a column stays ambiguous, add another
      faulty ciphertext for that diagonal.
"""

import itertools

SBOX = [
 0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
 0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
 0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
 0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
 0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
 0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
 0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
 0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
 0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
 0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
 0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
 0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
 0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
 0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
 0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
 0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16]
INVS = [0]*256
for _i, _v in enumerate(SBOX):
    INVS[_v] = _i

def _xt(a):
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a
def _gm(a, b):                                        # GF(2^8) multiply
    r = 0
    for _ in range(8):
        if b & 1: r ^= a
        b >>= 1; a = _xt(a)
    return r

MC  = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]       # MixColumns matrix
SR  = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]         # ShiftRows source map
ISR = [0]*16
for _i, _v in enumerate(SR):
    ISR[_v] = _i
GPOS = [[ISR[4*c + r] for r in range(4)] for c in range(4)]   # the 4 ciphertext diagonals

_RC = [0x00, 0x01]
while len(_RC) < 16:
    _RC.append(_xt(_RC[-1]))
_rot = lambda w: w[1:] + w[:1]
_sub = lambda w: [SBOX[b] for b in w]
_xor = lambda a, b: [x ^ y for x, y in zip(a, b)]

def invert_key_schedule(last_round_key, round_last=10):
    W = {}
    for j in range(4):
        W[4*round_last + j] = last_round_key[4*j:4*j + 4]
    for i in range(4*round_last + 3, 3, -1):
        t = _xor(_sub(_rot(W[i-1])), [_RC[i//4], 0, 0, 0]) if i % 4 == 0 else W[i-1]
        W[i-4] = _xor(W[i], t)
    return sum((W[j] for j in range(4)), [])

def _which_column(correct, faulty):
    diff = {i for i in range(16) if correct[i] != faulty[i]}
    for c in range(4):
        if diff and diff <= set(GPOS[c]):
            return c
    return None

def solve_column(correct, faulty, c, fault_values=range(1, 256)):
    pos = GPOS[c]; cands = set()
    for rho in range(4):                              # faulted row (unknown -> try all)
        for delta in fault_values:                    # fault value (covers multi-bit faults)
            target = [_gm(delta, MC[r][rho]) for r in range(4)]
            sols, ok = [], True
            for r in range(4):
                cp, cf = correct[pos[r]], faulty[pos[r]]
                sr = [k for k in range(256) if INVS[cp ^ k] ^ INVS[cf ^ k] == target[r]]
                if not sr: ok = False; break
                sols.append(sr)
            if ok:
                cands.update(itertools.product(*sols))
    return cands

def recover_master_key(correct, faulty_list, round_last=10, fault_values=range(1, 256)):
    col = [None]*4
    for Cf in faulty_list:
        c = _which_column(correct, Cf)
        if c is None:
            continue
        cand = solve_column(correct, Cf, c, fault_values)
        col[c] = cand if col[c] is None else (col[c] & cand)
    last_key = [None]*16
    for c in range(4):
        if not col[c] or len(col[c]) != 1:
            raise RuntimeError(f"column {c} unresolved ({0 if not col[c] else len(col[c])} candidates), feed more faults")
        tup = next(iter(col[c]))
        for r in range(4):
            last_key[GPOS[c][r]] = tup[r]
    return invert_key_schedule(last_key, round_last)


def _ct(h):
    h = h.strip().replace(" ", "")
    return [int(h[i:i+2], 16) for i in range(0, 32, 2)]

if __name__ == "__main__":
    correct = _ct(input("Correct ciphertext (32 hex): "))
    print("Faulty ciphertexts (32 hex), one per line, empty line to finish:")
    faulty = []
    while True:
        line = input("> ").strip()
        if not line:
            break
        faulty.append(_ct(line))
    rl = input("round_last [10]: ").strip() or "10"
    master = recover_master_key(correct, faulty, int(rl))
    print("\n[+] MASTER KEY:", "".join("%02x" % b for b in master))
