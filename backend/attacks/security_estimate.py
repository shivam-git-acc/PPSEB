"""PATCH 14 §1 — estimated bit-security of the trapdoor lattice.

Backend A (preferred): the Albrecht et al. lattice-estimator. It needs
SageMath, which is not installed here, so every result in this lab currently
comes from Backend B. The import is still attempted so the label is honest
about which one produced a number.

Backend B (fallback): the standard root-Hermite-factor route.
  - BKZ with root-Hermite factor delta_0 finds, in an m-dimensional q-ary
    lattice of determinant q^n, a vector of norm ~ delta_0^m * q^(n/m).
  - So breaking THIS lattice down to a target norm tau needs
        delta_0 <= (tau / q^(n/m))^(1/m).
  - Block size beta for that delta_0 comes from the standard fit
        delta_0(beta) = (beta/(2 pi e) * (pi beta)^(1/beta))^(1/(2(beta-1)))
    inverted numerically (delta_0 decreases in beta).
  - Cost in the core-SVP model: 2^(0.292 beta) classical (Becker-Ducas-Gama-
    Laarhoven), 2^(0.265 beta) quantum (Laarhoven). Reported as bits.

What `tau` is matters, so it is explicit and measured, never a tuned constant:
by default it is the honest key holder's OWN basis quality (its Gram-Schmidt
norm) at those parameters. The question the number answers is then "how much
BKZ does it take to find, from the public key alone, a basis as good as the
one the key holder has" -- exactly what the public-key-only attack does.

Caveats carried in every record, not just prose:
- The fit is the asymptotic one; below beta ~ 50 it is unreliable, so
  `fit_valid` says whether the answer sits in that range.
- This is a SIS-style estimate for the trapdoor lattice. It does not consume
  sigma; an LWE estimate of the ciphertext noise (Backend A's
  LWE.Parameters(Xs, Xe)) is a different question and is not what this
  reports.
"""

from __future__ import annotations

import math
from typing import Optional

from ppseb.params import derived_m

CLASSICAL_BIT_COST_PER_BETA = 0.292  # core-SVP, Becker-Ducas-Gama-Laarhoven
QUANTUM_BIT_COST_PER_BETA = 0.265  # core-SVP, Laarhoven
MIN_TRUSTWORTHY_BETA = 50
MAX_BETA = 2000


def lattice_estimator_available() -> bool:
    try:
        from estimator import LWE, ND  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 -- absence is the normal case here
        return False


def delta0_from_beta(beta: float) -> float:
    """The standard root-Hermite-factor fit for BKZ with block size beta."""
    if beta <= 2:
        return 1.0219  # LLL-ish; the fit is not defined at beta <= 2
    return (beta / (2 * math.pi * math.e) * (math.pi * beta) ** (1.0 / beta)) ** (1.0 / (2 * (beta - 1)))


def beta_for_delta0(delta0: float) -> Optional[int]:
    """Smallest block size reaching delta_0, searching only where the fit is
    monotone and meaningful (beta >= MIN_TRUSTWORTHY_BETA).

    The fit is NOT monotone below that: it dips around beta ~ 20 and rises
    again to beta = 50, so searching from small beta returns nonsense (it
    reported beta=3 for every parameter set). None means either "easier than
    beta=50" (delta0 above the fit's range) or "harder than MAX_BETA".
    """
    if delta0 >= delta0_from_beta(MIN_TRUSTWORTHY_BETA):
        return None  # target reachable below the fit's valid range
    for beta in range(MIN_TRUSTWORTHY_BETA, MAX_BETA + 1):
        if delta0_from_beta(beta) <= delta0:
            return beta
    return None


def required_delta0(n: int, q: int, m: int, target_norm: float) -> float:
    """delta_0 that brings an m-dim lattice of determinant q^n down to target_norm."""
    return (target_norm / q ** (n / m)) ** (1.0 / m)


def estimate_bits(n: int, q: int, m: int, target_norm: float, sigma: Optional[float] = None) -> dict:
    """Estimated cost of finding a basis as short as `target_norm` in L_perp_q(A)."""
    if lattice_estimator_available():  # pragma: no cover -- no Sage in this environment
        from estimator import LWE, ND
        params = LWE.Parameters(n=n, q=q, Xs=ND.DiscreteGaussian(sigma), Xe=ND.DiscreteGaussian(sigma))
        est = LWE.estimate(params)
        cheapest = min(est.items(), key=lambda kv: kv[1].rop)
        return {
            "backend": "lattice-estimator",
            "bits": float(math.log2(cheapest[1].rop)),
            "cheapest_attack": cheapest[0],
            "n": n, "q": q, "m": m, "sigma": sigma, "target_norm": target_norm,
            "fit_valid": True,
        }

    delta0 = required_delta0(n, q, m, target_norm)
    beta = beta_for_delta0(delta0) if delta0 > 1.0 else None
    below_fit_range = bool(delta0 > 1.0 and delta0 >= delta0_from_beta(MIN_TRUSTWORTHY_BETA))
    record = {
        "backend": "lindner-peikert-fit",
        "cheapest_attack": "BKZ on L_perp_q(A) (core-SVP cost model)",
        "n": n, "q": q, "m": m, "sigma": sigma,
        "target_norm": target_norm,
        "gaussian_heuristic": gaussian_heuristic(n, q, m),
        "required_delta0": delta0,
        "beta": beta,
        "bits": (CLASSICAL_BIT_COST_PER_BETA * beta) if beta else None,
        "bits_quantum": (QUANTUM_BIT_COST_PER_BETA * beta) if beta else None,
        "below_fit_range": below_fit_range,
        "bits_upper_bound": (CLASSICAL_BIT_COST_PER_BETA * MIN_TRUSTWORTHY_BETA) if below_fit_range else None,
        "fit_valid": bool(beta is not None and beta >= MIN_TRUSTWORTHY_BETA),
        "note": (
            "SIS-style estimate for the trapdoor lattice: cost of reaching a basis as short as "
            "target_norm. Does not consume sigma. Below beta=50 the root-Hermite fit is "
            "unreliable, which fit_valid reports."
        ),
    }
    if below_fit_range:
        record["note"] += (
            f" Target reachable below beta={MIN_TRUSTWORTHY_BETA}, where the fit is not "
            f"meaningful: the estimate is only an upper bound of about "
            f"{CLASSICAL_BIT_COST_PER_BETA * MIN_TRUSTWORTHY_BETA:.0f} bits."
        )
    if delta0 <= 1.0:
        record["note"] += " required_delta0 <= 1: no Hermite factor reaches this target, so the estimate is a lower bound only."
    return record


def gaussian_heuristic(n: int, q: int, m: int) -> float:
    """Expected shortest vector of L_perp_q(A): sqrt(m/(2 pi e)) * q^(n/m)."""
    return math.sqrt(m / (2 * math.pi * math.e)) * q ** (n / m)


def trapdoor_bytes(m: int, q: int) -> int:
    """PATCH 14 §4's size axis: m * ceil(log2 q) / 8."""
    return int(math.ceil(m * math.ceil(math.log2(q)) / 8))


def estimate_lwe_bits(n: int, q: int, sigma: float, m: Optional[int] = None) -> dict:
    """Cost of the primal lattice attack on LWE at (n, q, sigma).

    Theorem 1 reduces ciphertext indistinguishability to DECISION-LWE, which is
    a different problem from the short-basis/SIS question `estimate_bits`
    answers for the trapdoor lattice, so it gets its own entry point rather
    than quietly reusing that number. The instantiation is the same
    root-Hermite fit and the same core-SVP cost model, with the target set to
    the error norm sigma*sqrt(m) -- the quantity the primal attack has to reach
    for the LWE sample to be distinguishable.

    The provenance is carried in the result: where the fit is out of its
    trustworthy range the bits come back as an UPPER BOUND rather than a
    number, because at these dimensions the fit overstates difficulty and a
    confident figure would be the wrong kind of precision.
    """
    m = m or derived_m(n, q)
    target = sigma * math.sqrt(m)
    est = estimate_bits(n, q, m, target_norm=target, sigma=sigma)
    est["problem"] = "decision-LWE (primal)"
    est["target_provenance"] = f"error norm sigma*sqrt(m) = {target:.1f}"
    bits, upper = est.get("bits"), est.get("bits_upper_bound")
    # Three distinct outcomes, kept distinct instead of collapsing to None:
    #   a real beta            -> a number
    #   beta below the fit's floor -> an UPPER bound (the fit overstates
    #                             difficulty down here, so a point estimate
    #                             would be false precision)
    #   delta0 <= 1            -> the target is out of the fit's reach
    #                             entirely: the primal attack does not succeed
    #                             at any block size this backend covers, which
    #                             is not a bit count and must not be rendered
    #                             as one.
    est["beyond_fit_reach"] = bool(est.get("required_delta0", 0) <= 1.0)
    est["bits_effective"] = bits if bits is not None else upper
    est["is_upper_bound"] = bits is None and upper is not None
    if est["beyond_fit_reach"]:
        est["bits_effective"] = None
        est["note_reach"] = ("The primal attack does not reach the error norm at any block "
                             "size this fit covers, so its cost is not quantified here -- "
                             "that is a gap in the estimator, not a security claim.")
    return est
