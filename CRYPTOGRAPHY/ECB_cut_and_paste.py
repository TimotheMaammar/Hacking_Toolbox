"""
ECB cut-and-paste forgery.

USAGE
    When a service encrypts  PREFIX + attacker_input + SUFFIX  with a block cipher
    in ECB mode and later trusts the decrypted blob (token, cookie, session), and
    you control part of the plaintext. Lets you forge a blob that decrypts to a
    chosen plaintext (typically a privilege escalation) without the key.

HOW IT WORKS
    ECB encrypts each block independently, so ciphertext blocks are interchangeable.
    Each 16-byte block of the target is obtained from a separate oracle call by
    placing it on a block boundary; the final padded block is taken from a call
    whose plaintext ends with the needed tail. The blocks are then concatenated.

RUN
    Configure PREFIX / SUFFIX / TARGET and the oracle, then run. The provided oracle
    is manual: it prints the input to send and reads back the returned hex. Only a
    few queries are needed.

NOTES
    - The last block must carry valid padding, which can only come from the oracle,
      so its content is forced to be a suffix of SUFFIX. Make TARGET end with such a
      tail (e.g. a decoy key so a trailing `false}` is absorbed while the chosen
      value stays the winning one: duplicate JSON keys resolve to the last).
    - Every full block of TARGET must be expressible in the input field (mind bytes
      the field cannot carry, e.g. newline when the server does input().strip()).
"""

import os
import string


class ECBCutPaste:
    def __init__(self, block_size, prefix, suffix, oracle, filler=b"A"):
        self.bs = block_size
        self.prefix = prefix if isinstance(prefix, bytes) else prefix.encode()
        self.suffix = suffix if isinstance(suffix, bytes) else suffix.encode()
        self.oracle = oracle          # callable(user_bytes) -> ciphertext_bytes
        self.filler = filler

    def _nonce(self, n_blocks):
        # random letters to keep each oracle input unique (avoids "already exists")
        al = string.ascii_letters.encode()
        return bytes(al[b % len(al)] for b in os.urandom(self.bs * n_blocks))

    def block_of(self, content):
        # ciphertext of any 16-byte block, laid on a block boundary inside the input
        assert len(content) == self.bs
        align = (-len(self.prefix)) % self.bs                 # align the start of our input
        user = self.filler * align + content + self._nonce(1) # trailing nonce does not move the block
        ct = self.oracle(user)
        idx = (len(self.prefix) + align) // self.bs
        return ct[idx * self.bs:(idx + 1) * self.bs]

    def final_block(self, tail):
        # a last block = tail + valid padding, with tail == suffix[-len(tail):]
        r = len(tail)
        assert 0 < r < self.bs and bytes(tail) == self.suffix[-r:]
        base = (len(self.prefix) + len(self.suffix)) % self.bs
        L = (r - base) % self.bs
        user = self._nonce(1) + self.filler * L               # leading full block keeps uniqueness
        return self.oracle(user)[-self.bs:]

    def full_pad_block(self):
        # full padding block (only when TARGET length is a multiple of the block size)
        base = (len(self.prefix) + len(self.suffix)) % self.bs
        user = self._nonce(1) + self.filler * ((-base) % self.bs)
        return self.oracle(user)[-self.bs:]

    def forge(self, target):
        target = target if isinstance(target, bytes) else target.encode()
        full, r = divmod(len(target), self.bs)
        blocks = [self.block_of(target[i*self.bs:(i+1)*self.bs]) for i in range(full)]
        blocks.append(self.final_block(target[full*self.bs:]) if r else self.full_pad_block())
        return b"".join(blocks)


if __name__ == "__main__":
    from binascii import hexlify, unhexlify

    BLOCK  = int(input("block size [16]: ") or "16")
    PREFIX = (input('PREFIX text [{"username": "]: ') or '{"username": "').encode()
    SUFFIX = (input('SUFFIX text [", "isAdmin": false}]: ') or '", "isAdmin": false}').encode()
    TARGET = (input('TARGET plaintext [{"username": "admin", "isAdmin": true, "x": false}]: ')
              or '{"username": "admin", "isAdmin": true, "x": false}').encode()

    def oracle(user):
        print("\n[>] Send this to the encryption oracle:")
        print("    " + user.decode("latin-1"))
        return unhexlify(input("[<] Paste the returned ciphertext (hex): ").strip().replace(" ", ""))

    forged = hexlify(ECBCutPaste(BLOCK, PREFIX, SUFFIX, oracle).forge(TARGET)).decode()
    print("\n[*] Forged token:\n    " + forged)
