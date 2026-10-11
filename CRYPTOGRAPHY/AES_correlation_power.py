"""
USAGE
    Use this against a set of power (or electromagnetic) traces captured
    while a device performed AES encryption, together with the known
    plaintext for each trace. It recovers the 16 bytes of an AES-128
    first round key independently, one byte at a time, with no need to
    guess the key as a whole and no access to the device's internals.

        from aes_correlation_power_analysis import cpa_recover_key
        key, confidence = cpa_recover_key(plaintexts, traces)
        key_hex = key.tobytes().hex()

    plaintexts: a (n_traces, 16) uint8 array, one 16-byte AES block per
        trace. traces: a (n_traces, n_samples) array (any numeric dtype;
        it is converted to float internally) of the matching measurements,
        one row per trace, one column per sample point in time.

HOW IT WORKS
    This is standard Correlation Power Analysis (CPA) against AES. Real
    hardware draws current proportional, to a first approximation, to the
    number of bits that flip or that are set in the values it processes.
    The first round's SubBytes step computes SBox(plaintext_byte XOR
    key_byte) using only one key byte and one known plaintext byte at a
    time, so for each of the 16 key bytes independently: for every one of
    the 256 possible byte values, predict a leakage score (here, the
    Hamming weight of SBox(plaintext_byte XOR guess)) for every trace,
    then correlate that predicted score against the actual measurement at
    every sample point across all traces. Only the correct key guess
    predicts something that truly varies the same way real power draw
    does, so it produces a correlation peak, usually a sharp, narrow one
    at the exact sample where the SBox lookup happened, that stands out
    clearly above every wrong guess. The guess with the highest peak
    (by absolute value, since the sign depends on the device's power
    model) is taken as that key byte.

    This only ever needs the plaintext and the trace, never the
    ciphertext or the key, which is the whole point: it is a known
    plaintext physical side channel attack, not a mathematical one.

RUN
    key, confidence = cpa_recover_key(plaintexts, traces)

    confidence is a list of (best_peak, runner_up_peak) pairs, one per key
    byte; a wide gap between the two means a confident recovery, a narrow
    one is worth double checking (more traces, or a different leakage
    model, usually resolves it).

    To confirm the recovered key is actually correct, encrypt a known
    plaintext with it using any standard AES library (for example
    `cryptography` or `pycryptodome`, ECB mode, no padding needed for a
    single 16 byte block) and compare against the real ciphertext for
    that trace, if you have it. A handful of 200 traces is often more
    than enough for a software implementation with no countermeasures;
    noisier or protected targets need more.

NOTES
    - The default leakage model predicts the Hamming weight of the first
      round SubBytes output. If that does not produce a clean peak for
      every byte, the target may leak a different intermediate value (a
      later round, a different operation, a masked implementation) and
      correlate_columns and cpa_recover_key_byte are exposed separately so
      a different hypothesis matrix can be substituted.
    - Traces recorded with a different sample count per trace, or not
      aligned in time against each other, will weaken or hide the
      correlation peak; this implementation assumes traces are already
      time aligned and of equal length, which is the common case for
      traces distributed for analysis.
    - Needs numpy. The correlation is fully vectorized (one matrix
      multiply per key byte across all 256 guesses and every sample
      point), so even traces with tens of thousands of samples and
      hundreds of guesses finish in well under a second per key byte.
"""

import numpy as np

SBOX = np.array([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
], dtype=np.uint8)

HAMMING_WEIGHT = np.array([bin(x).count("1") for x in range(256)], dtype=np.float64)


def correlate_columns(H, T):
    """Pearson correlation between every column of H and every column of T.

    H: (n_traces, n_hypotheses). T: (n_traces, n_samples).
    Returns (n_hypotheses, n_samples), fully vectorized with one matrix
    multiply; this is the expensive step done once per key byte.
    """
    Hc = H - H.mean(axis=0, keepdims=True)
    Tc = T - T.mean(axis=0, keepdims=True)
    num = Hc.T @ Tc
    Hstd = np.sqrt((Hc ** 2).sum(axis=0))
    Tstd = np.sqrt((Tc ** 2).sum(axis=0))
    denom = np.outer(Hstd, Tstd)
    denom[denom == 0] = np.nan
    return num / denom


def cpa_recover_key_byte(plaintext_byte, traces, leakage_table=None):
    """Recover one AES-128 first round key byte.

    plaintext_byte: (n_traces,) uint8, the same plaintext byte position
        across all traces.
    traces: (n_traces, n_samples), any numeric dtype.
    leakage_table: optional (256,) array mapping an SBox output byte to a
        predicted leakage score; defaults to Hamming weight.

    Returns (best_guess, peak_per_guess) where peak_per_guess is a (256,)
    array of each guess's best absolute correlation across all samples.
    """
    if leakage_table is None:
        leakage_table = HAMMING_WEIGHT
    guesses = np.arange(256, dtype=np.uint8)
    xored = plaintext_byte[:, None] ^ guesses[None, :]
    sbox_out = SBOX[xored]
    H = leakage_table[sbox_out]
    corr = correlate_columns(H, traces)
    peak_per_guess = np.nanmax(np.abs(corr), axis=1)
    best_guess = int(np.argmax(peak_per_guess))
    return best_guess, peak_per_guess


def cpa_recover_key(plaintexts, traces, leakage_table=None, log=None):
    """Recover all 16 bytes of an AES-128 first round key.

    plaintexts: (n_traces, 16) uint8. traces: (n_traces, n_samples).
    Returns (key, confidence): key is a (16,) uint8 array, confidence is a
    list of (best_peak, runner_up_peak) tuples, one per byte.
    """
    traces = np.asarray(traces, dtype=np.float64)
    key = np.zeros(16, dtype=np.uint8)
    confidence = []
    for i in range(16):
        best_guess, peaks = cpa_recover_key_byte(plaintexts[:, i].astype(np.uint8), traces, leakage_table)
        sorted_peaks = np.sort(peaks)
        best_peak, runner_up = sorted_peaks[-1], sorted_peaks[-2]
        key[i] = best_guess
        confidence.append((float(best_peak), float(runner_up)))
        if log:
            log(f"byte {i:2d}: key=0x{best_guess:02x}, peak={best_peak:.3f}, "
                f"runner up={runner_up:.3f}, margin={best_peak-runner_up:.3f}")
    return key, confidence
