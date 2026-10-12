"""
USAGE
    Use this when an RSA private exponent d has partially leaked (for
    example through a cold boot attack, a timing side channel, or a
    corrupted key backup) and a CONTIGUOUS block of its least significant
    bits is known exactly, with everything above that unknown. Combined
    with a small public exponent e, this recovers the full private key
    and factors the modulus, without ever seeing a ciphertext or an
    oracle: it is pure number theory on the public key plus the leaked
    bits.

        from rsa_partial_key_exposure import recover_key_from_partial_d
        result = recover_key_from_partial_d(N, e, d_known=d_low_bits, M=1400)
        if result:
            p, q, d, k = result

    N, e: the RSA public key. d_known: the known low M bits of d, as a
    plain integer (d mod 2^M). M: how many low bits are known.

HOW IT WORKS
    This is the Boneh-Durfee-Frankel partial key exposure attack. Since
    ed = 1 + k*phi(N) for some integer k < e, and e is small, there are
    only a handful of candidate k values to try (brute force over k is
    what makes this attack only work for small e). For the correct k,
    the known low bits of d pin down phi(N), and therefore p+q, modulo
    the same power of two. From there, a second elementary step (Hensel
    lifting the relation p + N/p = p+q, working one bit at a time)
    recovers that many low bits of p itself, not just of p+q. Critically,
    this lifting step cannot distinguish the correct k from a wrong one
    on its own: it produces an internally consistent candidate for every
    k, right or wrong, so every surviving k must be carried forward.

    The known low bits of p rarely cover p's full length (needing a
    fraction of d's bits that shrinks as e shrinks, roughly a quarter of
    N's bit length in the classic case). The remaining high bits of p are
    recovered with Coppersmith's method: build a small lattice of
    polynomials that all vanish at the unknown part modulo a high power
    of p, reduce it with LLL, and a short enough vector gives a
    polynomial that vanishes at that unknown part as an exact integer
    equation, which is then solved directly. Only the correct k produces
    a value that actually divides N; every wrong k is discarded at this
    final check, which is what truly identifies the right one. Because
    testing each k is independent, this step parallelizes trivially
    across processes.

RUN
    result = recover_key_from_partial_d(N, e, d_known, M, log=print)
    if result:
        p, q, d, k = result
        phi = (p - 1) * (q - 1)
        assert pow(e * d, 1, phi) == 1 % phi

    Useful knobs:
    - workers: how many candidate (k, partial-p) pairs to test in
      parallel via separate processes (default: os.cpu_count()).
    - coppersmith_m: the lattice size parameter for the final recovery
      step (default 2). Only raise it if recovery fails and you know the
      known fraction of bits is close to the theoretical limit; each
      increment roughly doubles the lattice dimension and the runtime.
    - decimal_precision: working precision for the internal LLL's
      floating point steps (default 1500 decimal digits). This needs to
      scale with the bit length of N; the default comfortably covers
      moduli up to several thousand bits, but very large keys may need
      more (if recovery silently fails, this is the first thing to
      raise, by doubling it).

NOTES
    - The known bits must be a contiguous block starting at bit 0 (the
      least significant end), not scattered individual bits; that
      structure is what makes both the elementary lifting step and the
      Coppersmith step work. Scattered known bits across a full CRT key
      (p, q, d, dp, dq) call for a different algorithm (Heninger-Shacham
      style branch and prune), not this one.
    - How many bits you need depends on e: smaller e needs fewer known
      bits of d. A rough rule of thumb from the original analysis is
      about one quarter of N's bit length for small, fixed e; comfortably
      more than that gives a wide safety margin and a cheaper
      coppersmith_m. Size M against the bit length of the prime factors
      (roughly half of N's bit length for balanced two-prime RSA), not
      against d's own bit length: M known low bits of d translate 1:1
      into M known low bits of p, so M must stay under p's bit length or
      there is nothing left for Coppersmith's step to recover.
    - The LLL implementation here is a plain, from scratch one (Decimal
      based Gram-Schmidt, full recomputation every step) chosen for
      portability, since fast C-backed lattice libraries are often hard
      to install without a build toolchain. It is adequate for the small
      lattice dimensions this attack needs (dimension 2*coppersmith_m,
      typically 4 to 10) but is not a general purpose LLL implementation;
      do not reuse it for much larger lattices without optimizing it
      first (incremental Gram-Schmidt updates instead of full
      recomputation would be the first and biggest win).
    - This never needs a live oracle or network access; everything runs
      offline against the public key and the leaked bits.
    - recover_key_from_partial_d uses a process pool, which on Windows
      re-imports whatever script called it in every worker process. Wrap
      your call in `if __name__ == "__main__":` (the standard
      multiprocessing idiom), or the worker processes will try to spawn
      their own process pools recursively and crash.
"""

import math
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from decimal import Decimal, getcontext


# ----------------------------------------------------------------------
# A small, portable LLL implementation (Decimal-based Gram-Schmidt).
# ----------------------------------------------------------------------

def _set_precision(digits):
    getcontext().prec = digits


def _gram_schmidt(B):
    n = len(B)
    Bstar = [None] * n
    mu = [[Decimal(0)] * n for _ in range(n)]
    norms = [None] * n
    for i in range(n):
        v = [Decimal(x) for x in B[i]]
        for j in range(i):
            num = sum(Decimal(B[i][k]) * Bstar[j][k] for k in range(len(B[i])))
            mu[i][j] = num / norms[j] if norms[j] != 0 else Decimal(0)
            v = [v[k] - mu[i][j] * Bstar[j][k] for k in range(len(v))]
        Bstar[i] = v
        norms[i] = sum(x * x for x in v)
    return Bstar, mu, norms


def _lll_reduce(B, delta=Decimal("0.75")):
    B = [row[:] for row in B]
    n = len(B)
    Bstar, mu, norms = _gram_schmidt(B)
    k = 1
    while k < n:
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > Decimal("0.5"):
                q = int(mu[k][j].to_integral_value(rounding="ROUND_HALF_EVEN"))
                if q != 0:
                    B[k] = [B[k][t] - q * B[j][t] for t in range(len(B[k]))]
                    Bstar, mu, norms = _gram_schmidt(B)
        lhs = norms[k]
        rhs = (delta - mu[k][k - 1] ** 2) * norms[k - 1]
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            Bstar, mu, norms = _gram_schmidt(B)
            k = max(k - 1, 1)
    return B


# ----------------------------------------------------------------------
# Coppersmith's method for a monic linear modular polynomial: given
# f(x) = x + c with f(x0) = 0 (mod p) for an unknown divisor p of N with
# p >= sqrt(N), and a bound |x0| < X, recover x0.
# ----------------------------------------------------------------------

def _f_power_coeffs(c, power):
    return [math.comb(power, j) * (c ** (power - j)) for j in range(power + 1)]


def _poly_eval(coeffs, x):
    total, p = 0, 1
    for cf in coeffs:
        total += cf * p
        p *= x
    return total


def _poly_deriv(coeffs):
    return [i * coeffs[i] for i in range(1, len(coeffs))]


def _isqrt_if_perfect_square(n):
    if n < 0:
        return None
    r = math.isqrt(n)
    return r if r * r == n else None


def _integer_roots_small_degree(coeffs, bound, iters=80):
    deg = len(coeffs) - 1
    while deg > 0 and coeffs[deg] == 0:
        deg -= 1
    if deg <= 0:
        return []
    coeffs = coeffs[:deg + 1]

    if deg == 1:
        a, b = coeffs[1], coeffs[0]
        if b % a == 0:
            cand = -b // a
            if abs(cand) <= bound:
                return [cand]
        return []

    if deg == 2:
        a, b, c = coeffs[2], coeffs[1], coeffs[0]
        disc = b * b - 4 * a * c
        root = _isqrt_if_perfect_square(disc)
        if root is None:
            return []
        found = []
        for num in (-b + root, -b - root):
            if num % (2 * a) == 0:
                cand = num // (2 * a)
                if abs(cand) <= bound and _poly_eval(coeffs, cand) == 0:
                    found.append(cand)
        return list(set(found))

    dcoeffs = _poly_deriv(coeffs)
    found = []
    for x0 in (0, bound // 4, -(bound // 4), bound // 2, -(bound // 2), bound, -bound):
        x = x0
        for _ in range(iters):
            fx = _poly_eval(coeffs, x)
            if fx == 0:
                break
            dfx = _poly_eval(dcoeffs, x)
            if dfx == 0:
                break
            delta = fx // dfx
            if delta == 0:
                delta = 1 if fx > 0 else -1
            x_new = x - delta
            if x_new == x:
                break
            x = x_new
        for cand in range(x - 2, x + 3):
            if abs(cand) <= bound and _poly_eval(coeffs, cand) == 0:
                found.append(cand)
    return list(set(found))


def find_small_root_linear(c, N, X, m, t=None, decimal_precision=1500):
    """f(x) = x + c, find x0 with |x0| < X and f(x0) = 0 (mod p) for an
    unknown divisor p of N with p >= sqrt(N). Returns candidate integer
    roots (verify by checking whether they actually divide N, since a
    wrong input c will generally yield none, but occasionally a spurious
    one is worth a cheap double check).

    t defaults to m, the standard choice for p >= sqrt(N) (beta = 0.5).
    Two families of shift polynomials are used, g_i = N^(m-i) * f(x)^i
    for i = 0..m-1 and h_j = x^j * f(x)^m for j = 0..t-1; the second
    family is essential and a naive single-family construction will not
    reach a short enough lattice vector.
    """
    if t is None:
        t = m
    _set_precision(decimal_precision)

    polys = []
    for i in range(m):
        base = _f_power_coeffs(c, i)
        polys.append([v * (N ** (m - i)) for v in base])
    fm = _f_power_coeffs(c, m)
    for j in range(t):
        polys.append([0] * j + list(fm))

    dim = len(polys)
    B = [[0] * dim for _ in range(dim)]
    for row_idx, coeffs in enumerate(polys):
        for j, v in enumerate(coeffs):
            B[row_idx][j] = v * (X ** j)

    reduced = _lll_reduce(B)

    candidates = []
    for row in reduced:
        if all(v == 0 for v in row):
            continue
        coeffs, ok = [], True
        for j, v in enumerate(row):
            if v % (X ** j) != 0:
                ok = False
                break
            coeffs.append(v // (X ** j))
        if not ok:
            continue
        candidates.extend(_integer_roots_small_degree(coeffs, X))
    return list(set(candidates))


# ----------------------------------------------------------------------
# The partial key exposure attack itself.
# ----------------------------------------------------------------------

def _v2(n):
    if n == 0:
        return float("inf")
    c = 0
    while n % 2 == 0:
        n //= 2
        c += 1
    return c


def _phi_mod_candidates(N, e, d_known, M):
    """For every candidate k in 1..e-1, solve k*phi = ed_known - 1 (mod
    2^M) for phi, to whatever precision the 2-adic valuation of k allows.
    Returns a list of (k, phi_mod, precision)."""
    v = (e * d_known - 1) % (2 ** M)
    out = []
    for k in range(1, e):
        a = _v2(k)
        if a >= M or v % (2 ** a) != 0:
            continue
        mod = 2 ** (M - a)
        k_odd = k >> a
        rhs = (v >> a) % mod
        phi_mod = (rhs * pow(k_odd, -1, mod)) % mod
        out.append((k, phi_mod, M - a))
    return out


def _lift_p_candidates(N, s_mod, precision, max_survivors=64):
    """Hensel-lift candidates for p mod 2^precision from s = p+q mod
    2^precision (via p + N/p = s, checked bit by bit). This does not by
    itself distinguish a correct s from an incorrect one; every input
    typically yields a handful of internally consistent survivors."""
    survivors = [1]
    for t in range(2, precision + 1):
        mod = 1 << t
        s_t = s_mod % mod
        next_survivors = []
        for p0 in survivors:
            for cand in (p0, p0 + (1 << (t - 1))):
                cand &= (mod - 1)
                try:
                    inv = pow(cand, -1, mod)
                except ValueError:
                    continue
                q0 = (N * inv) % mod
                if (cand + q0) % mod == s_t:
                    next_survivors.append(cand)
        survivors = list(set(next_survivors))
        if not survivors:
            return []
        if len(survivors) > max_survivors:
            raise RuntimeError(f"survivor explosion at t={t}: {len(survivors)}")
    return survivors


def _try_one_candidate(args):
    N, e, k, p0, precision, p_bits_estimate, coppersmith_m, decimal_precision = args
    r = 1 << precision
    unknown_bits = p_bits_estimate - precision
    if unknown_bits <= 0:
        return None
    X = 1 << (unknown_bits + 2)
    c = (p0 * pow(r, -1, N)) % N
    try:
        roots = find_small_root_linear(c, N, X, coppersmith_m, decimal_precision=decimal_precision)
    except Exception:
        return None
    for x0 in roots:
        p_cand = p0 + r * x0
        if p_cand > 1 and N % p_cand == 0:
            return k, p_cand
    return None


def recover_key_from_partial_d(N, e, d_known, M, p_bits_estimate=None,
                                coppersmith_m=2, decimal_precision=1500,
                                workers=None, log=None):
    """Recover the RSA private key given only the low M bits of d.

    N, e: public key. d_known: integer equal to d mod 2^M. M: how many
    low bits of d are known.
    p_bits_estimate: expected bit length of the smaller prime factor;
    defaults to half of N's bit length plus a small margin, the standard
    case for balanced two-prime RSA.

    Returns (p, q, d, k) on success, or None if no candidate worked (try
    raising coppersmith_m, or confirm M is large enough: see NOTES).
    """
    if p_bits_estimate is None:
        p_bits_estimate = N.bit_length() // 2 + 4
    if M >= p_bits_estimate:
        raise ValueError(
            f"M ({M}) is not smaller than p_bits_estimate ({p_bits_estimate}); "
            "M must be sized against the bit length of a prime factor, not "
            "against d's own bit length (see NOTES), or there is nothing left "
            "for Coppersmith's step to recover"
        )
    workers = workers if workers is not None else (os.cpu_count() or 4)

    phi_candidates = _phi_mod_candidates(N, e, d_known, M)
    if log:
        log(f"{len(phi_candidates)} candidate k values pass the elementary filter")

    tasks = []
    for k, phi_mod, precision in phi_candidates:
        s_mod = (N + 1 - phi_mod) % (2 ** precision)
        try:
            p_candidates = _lift_p_candidates(N, s_mod, precision)
        except RuntimeError:
            continue
        for p0 in p_candidates:
            tasks.append((N, e, k, p0, precision, p_bits_estimate, coppersmith_m, decimal_precision))

    if log:
        log(f"{len(tasks)} (k, partial-p) candidates to test with Coppersmith's method")

    ex = ProcessPoolExecutor(max_workers=workers)
    try:
        futs = {ex.submit(_try_one_candidate, t): t for t in tasks}
        for i, fut in enumerate(as_completed(futs), 1):
            result = fut.result()
            if log and i % 20 == 0:
                log(f"  tested {i}/{len(tasks)} candidates")
            if result:
                k, p = result
                q = N // p
                phi = (p - 1) * (q - 1)
                assert (1 + k * phi) % e == 0, "inconsistent k/p pair (should not happen)"
                d = (1 + k * phi) // e
                assert (e * d) % phi == 1, "recovered d fails the RSA key equation (should not happen)"
                return p, q, d, k
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return None
