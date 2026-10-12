"""
USAGE
    Use this when one of the two CRT private exponents from an RSA key
    has leaked on its own (dp = d mod (p-1), or dq = d mod (q-1)), with
    or without the rest of the key. This recovers the matching prime
    factor directly, in a brute force search bounded only by the size of
    the public exponent e, with no lattice reduction and no partial-bit
    requirement: a single complete CRT exponent is enough by itself.

        from rsa_crt_exponent_factor_recovery import recover_prime_from_crt_exponent
        p = recover_prime_from_crt_exponent(dp, e)
        q = recover_prime_from_crt_exponent(dq, e)   # if dq is also known
        N = p * q                                     # once both are known

    A single CRT exponent, dp or dq, recovers only its own matching
    prime; recovering the full modulus needs either both, or one of them
    together with N from elsewhere (N // p gives the other factor).

HOW IT WORKS
    By definition dp = d mod (p-1), and since ed = 1 mod phi(N), it is
    also true that ed = 1 mod (p-1), because (p-1) divides phi(N). So
    e*dp - 1 is an exact multiple of (p-1): e*dp - 1 = m*(p-1) for some
    positive integer m. Because dp < p-1, and e is the only other factor
    in play, m is bounded by e, usually well below it in practice. That
    makes m cheap to brute force: for each candidate m from 1 up to e-1,
    check whether m divides e*dp - 1 evenly, and if so, whether the
    resulting (e*dp - 1)/m + 1 is prime. The one that is, is p. The same
    reasoning applies unchanged to dq and q.

    This is a much more direct relative of the classical small-e
    "recover p and q from the full private exponent d" algorithm (the
    one built around ed - 1 = k*phi(N)). Using a CRT exponent instead of
    d skips the need to also search for phi(N) or q, because a CRT
    exponent is tied to a single prime from the start.

RUN
    p = recover_prime_from_crt_exponent(dp, e)
    if p is None:
        # try the other CRT exponent, or widen max_m if e is unusually
        # large and you suspect m exceeds the default search range
        p = recover_prime_from_crt_exponent(dp, e, max_m=2 * e)

    Once you have one prime and the modulus N from elsewhere, the rest
    follows with ordinary arithmetic:
        q = N // p
        d = pow(e, -1, (p - 1) * (q - 1))

NOTES
    - e does not need to be unusually small for this to be practical the
      way it does for lattice based partial key exposure attacks; e up
      to the tens of thousands tests in well under a second, and even
      e = 65537, the common default, finishes instantly. What matters is
      that m stays small, and m is bounded by e by construction.
    - A dp or dq value packaged in a PKCS#1 RSAPrivateKey DER structure
      sits between prime2 (q) and the coefficient, as the seventh and
      eighth INTEGER fields in the SEQUENCE (version, n, e, d, p, q, dp,
      dq, coefficient); each one is normally about as many bits as its
      matching prime, the same size as p and q themselves. That makes dp
      and dq easy to mistake for p and q in a partially corrupted key
      file, and easy to positively identify too: an INTEGER field the
      right size to be a prime factor that fails a primality check is
      almost certainly dp, dq, or the coefficient instead, whether or not
      p and q are visible anywhere nearby to compare against.
    - If the input value is not actually a CRT exponent for the implied
      e (wrong e guessed, or just the wrong number entirely), the search
      usually finds no prime at all rather than a false positive, since
      requiring both exact divisibility and primality is a strong
      combined filter.
"""


def _is_probable_prime(n, rounds=20):
    import random
    if n < 2:
        return False
    for sp in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % sp == 0:
            return n == sp
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(rounds):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def recover_prime_from_crt_exponent(crt_exponent, e, max_m=None, min_bits=0):
    """Recover the prime p such that crt_exponent = d mod (p-1), given
    the public exponent e.

    crt_exponent: dp or dq, as an integer.
    e: the public exponent.
    max_m: upper bound on the search for the small multiplier m (default
        e - 1, the theoretical bound).
    min_bits: reject candidates below this many bits, useful to rule out
        tiny false positives when testing against unusually small inputs
        (default 0, no filtering).

    Returns the recovered prime, or None if no candidate in range both
    divides evenly and passes a primality check.
    """
    if max_m is None:
        max_m = e - 1
    target = e * crt_exponent - 1
    for m in range(1, max_m + 1):
        if target % m != 0:
            continue
        candidate = target // m + 1
        if candidate.bit_length() < min_bits:
            continue
        if candidate > 1 and _is_probable_prime(candidate):
            return candidate
    return None
