"""
USAGE
    Use this when you hold one legitimate share of a Shamir secret
    sharing scheme and get to submit it to a reconstruction process that
    combines it with other, unknown shares (held by other parties you do
    not trust, or do not want to trust with the real secret). Submitting
    a deliberately wrong share steers the reconstructed result to a
    value of your choosing, computed in advance, without ever learning
    the other parties' shares. A second query, of any kind that reveals
    the resulting integer, is also enough to recover the real secret
    afterward, even though you never submitted your real share.

        from shamir_share_malleability import (
            lagrange_coefficient_at_zero,
            recover_secret_from_shifted_result,
            craft_share_for_target,
        )

        # all_xs can include my_x or not, either way works
        my_coeff = lagrange_coefficient_at_zero(my_x, all_xs, p)

        # one query with a share you shifted by a known delta reveals
        # the real secret, even though the result you see is wrong
        real_secret = recover_secret_from_shifted_result(
            observed_result, delta_used, my_coeff, p)

        # now steer a later reconstruction to any integer you want
        fake_share = craft_share_for_target(
            my_real_share, target_value, real_secret, my_coeff, p)

HOW IT WORKS
    Reconstructing a Shamir secret is Lagrange interpolation at x = 0,
    which is a strictly linear function of the shares: secret = sum of
    y_i * L_i(0) over all participants i, where each L_i(0) is a fixed
    constant depending only on the set of x-coordinates in use, never on
    the y-values. That means your own share's contribution to the final
    result is exactly y_you * L_you(0), and nothing else about your
    share matters to the computation.

    Two consequences follow directly from that linearity. First, if you
    submit y_you + delta instead of your real share, the reconstructed
    result shifts by exactly delta * L_you(0), regardless of what the
    other, unknown shares are. Second, that same relationship can be run
    in either direction: seeing any one result for a known delta reveals
    the real secret (solve for it), and knowing the real secret lets you
    solve for the delta that produces any target result you like. A
    single query is enough to learn the real secret, because the
    unknown contribution from everyone else's shares is a fixed
    constant that cancels out of the equation once you know your own
    delta and your own Lagrange coefficient.

    This only works because secret sharing reconstruction is linear by
    construction; it says nothing about the discrete log or factoring
    hardness of anything else in the system, and it does not require
    knowing or guessing any other participant's share.

RUN
    lagrange_coefficient_at_zero(x, other_xs, p):
        x: your own x-coordinate. other_xs: the x-coordinates of every
        participant, yours included or not, either is fine. p: the field
        modulus. Returns L_x(0), the fixed multiplier your share's
        deviation gets scaled by in the final result.

    recover_secret_from_shifted_result(observed_result, delta, coeff, p):
        observed_result: the integer the reconstruction produced after
        you submitted your_real_share + delta. delta: the amount you
        added (can be any value; a large one is useful to guarantee a
        visibly wrong, obviously-not-your-target result if you need the
        process to treat it as a failed attempt rather than a success).
        Returns the real secret.

    craft_share_for_target(real_share, target_value, real_secret, coeff, p):
        Returns the share value to submit so the reconstruction produces
        exactly target_value. target_value is the secret as an integer;
        encode bytes with int.from_bytes(data, "big") first if the
        secret is text or binary data, and make sure it is smaller than
        p (and, if the real scheme pads or wraps its secrets in a
        specific byte length, matches that length, since the receiving
        side will decode exactly len(data) worth of bytes regardless of
        what you intended).

NOTES
    - You need the full set of x-coordinates in use (yours and
      everyone else's) to compute your Lagrange coefficient; these are
      ordinarily public parameters of the scheme, not secret.
    - If the process only ever shows you the final decoded value when
      it looks "valid" in some way (readable text, correct checksum,
      and so on) and otherwise asks you to retry, that retry itself
      typically still reveals the resulting integer; use it as the one
      query recover_secret_from_shifted_result needs, with whatever
      delta you used for that attempt.
    - The target integer must be strictly less than the field modulus p,
      the same requirement every share and every secret in the scheme
      is already bound by.
    - This assumes you get to see the numeric result of at least one
      reconstruction attempt using your own share. If the system only
      ever reports success or failure with no number attached, this
      specific technique has nothing to work with; look for some other
      channel that leaks the reconstructed integer instead.
"""


def lagrange_coefficient_at_zero(x, other_xs, p):
    """L_x(0) for participant x, given the x-coordinates of every other
    participant in the scheme and the field modulus p. other_xs may be
    passed either excluding x or as the full participant list including
    it; x is filtered out either way, since a 0 term in the denominator
    (from including x in other_xs) is not a usable result in any case."""
    other_xs = [xj for xj in other_xs if xj != x]
    num, den = 1, 1
    for xj in other_xs:
        num = (num * (-xj)) % p
        den = (den * (x - xj)) % p
    return (num * pow(den, -1, p)) % p


def recover_secret_from_shifted_result(observed_result, delta, coeff, p):
    """Recover the real secret from one reconstruction that used
    your_real_share + delta instead of your real share."""
    return (observed_result - delta * coeff) % p


def craft_share_for_target(real_share, target_value, real_secret, coeff, p):
    """Compute the share to submit so reconstruction yields target_value,
    given the real secret (from recover_secret_from_shifted_result) and
    your Lagrange coefficient."""
    delta = ((target_value - real_secret) * pow(coeff, -1, p)) % p
    return (real_share + delta) % p
