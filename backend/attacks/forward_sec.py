"""Finding 2 — forward-security norm experiment.

PATCH 01 reframing: the paper omits H1's construction, and the two natural
instantiations FAIL DIFFERENTLY. That dilemma — not a single clean "broken"
or "safe" verdict — IS Finding 2.

- **naive_uniform H1** (R = uniform invertible mod q): ||R|| ~ q/2, so
  NewBasisDel inflates the delegated basis norm by a large factor each
  period -> **KeyExt loses correctness within a few periods.** Forward
  security is moot because the scheme doesn't even function: there is no
  usable *legitimate* trapdoor to protect. We report this as
  "correctness collapse at period k", not as a forward-security verdict.

- **low_norm H1** (R = I + strictly-upper-triangular small N): correctness
  holds (the legitimate chain stays usable), but R^-1 is *also* low-norm, so
  the public transform R^-1 . sk_J yields a valid (long) earlier-period
  basis, and **LLL re-reduction recovers a USABLE earlier basis for recent
  periods** at these demo parameters -> a genuine forward-security weakness.

Net finding: *both* natural H1 choices lose — one to correctness, one to
forward security. The proof's silence on H1's distribution is load-bearing.

**Claim under test:** stealing the CURRENT period's trapdoor sk_rJ must not
reveal any EARLIER period's trapdoor sk_ri (i < J).

**Reduction:** consecutive periods are related by a PUBLIC invertible
transform R_j = H1(pk_r{j-1}, j): pk_rj = pk_r{j-1} . R_j^-1 (mod q).
Chaining periods i+1..J gives pk_rJ = pk_ri . P^-1 (mod q) for
P = R_J . R_{J-1} ... . R_{i+1}. Since pk_rJ . sk_rJ = 0 (mod q):

    pk_ri . (P^-1 . sk_rJ) = (pk_ri . P^-1) . sk_rJ = pk_rJ . sk_rJ = 0 (mod q)

holds UNCONDITIONALLY, regardless of how sk_rJ was produced. So
`cand_i = P^-1 . sk_rJ` is ALWAYS a valid candidate basis of L_perp_q(pk_ri),
computable from public data plus one stolen sk_rJ. The only open question is
whether it (or its own LLL re-reduction) is short enough to be USABLE.

**R^-1 audit (over Z vs mod q):** each low_norm R_j = I + N has det = 1
EXACTLY over Z, so it has a genuine integer inverse (hashes.H1_inverse, via
back-substitution — no division ever needed). We build P^-1 by chaining the
mod-q reductions of those exact inverses one step at a time; this is
mathematically forced to agree with "multiply the exact-over-Z inverses
first, reduce the product mod q once at the end" (mod-q reduction is a ring
homomorphism), and test_r_inverse_over_z_matches_incremental_mod_q verifies
the two computations agree on every entry. For naive_uniform, "over Z"
doesn't apply at all: a uniformly random mod-q-invertible matrix has no
reason to have determinant +/-1 over Z, so it has no integer inverse, only
a mod-q one.

**Balanced representatives:** every matrix's entries only need to be correct
MOD q, so any two representatives of the same residue describe the same
lattice point. Left un-reduced (e.g. in [0, q)), Gram-Schmidt norms are
artifacts of the arithmetic, not real quantities — this applies BOTH to the
attacker's candidate AND to the legitimate chain's own sk_j (`_build_chain`
balances before measuring `legit_gs`, per PATCH 01 §3).

**LLL re-reduction:** a balanced-but-unreduced candidate is *some* valid
basis of L_perp_q(pk_ri), not necessarily a good one. The honest question is
what the attacker gets after doing what our own NewBasisDel does: LLL-reduce
it. Every candidate is measured twice (trivial, then after LLL).

**Explicit usability threshold (PATCH 01 §2):** "usable" is not an
unexplained q/4. A basis is usable for SamplePre at width sigma only if its
Gram-Schmidt norm respects BOTH the sampling bound (sigma must dominate the
norm by omega(sqrt(log m)), the standard GPV/ABB smoothing condition) and
the decode bound (the resulting preimage's noise must stay under Verify's
q/4 margin). `usability_threshold` computes both caps and reports which one
binds, so the number driving every verdict is visible and justified.

**Honesty requirement (CLAUDE.md §4):** every verdict is DERIVED from
measured Gram-Schmidt norms against the explicit threshold above, never
hard-coded.

**Parameter-scaling caveat:** at n=4, LLL is near-optimal, so a "BROKEN
after LLL" result does not establish a break at cryptographic parameters —
scaling that claim requires BKZ analysis at secure n, which this lab does
not perform. The finding is: forward security reduces to lattice reduction
on R^-1.sk_J, and at these DEMO parameters that reduction succeeds for
recent periods.
"""

from __future__ import annotations

import math
import random

import numpy as np

from ppseb.hashes import H1, H1_inverse
from ppseb.linalg import (
    centered_mod_q, fpylll_available, gram_schmidt_norm, lll_reduce, mat_inv_mod, mat_mod_mixed,
    matrix_col_norm, safe_matmul, strong_reduce,
)
from ppseb.params import Params
from ppseb.samplers import new_basis_del
from ppseb.trace import Trace
from ppseb.trapgen import trapgen

H1_VARIANTS = ("low_norm", "naive_uniform")

SCALING_CAVEAT = (
    "Demonstration parameters (n={n}). LLL is near-optimal in low dimension, "
    "so recovery here does not establish a break at secure parameters. "
    "Scaling requires BKZ analysis at cryptographic n, which this lab does "
    "not perform. The result shown is: the forward-security question "
    "reduces to lattice reduction on R^-1.sk_J, and at demo params that "
    "reduction succeeds for recent periods."
)


def usability_threshold(params: Params) -> dict:
    """SINGLE SOURCE OF TRUTH (PATCH 02 §A.2) for "is a basis with
    Gram-Schmidt norm g usable as a trapdoor for SamplePre at width
    params.sigma?" Every consumer — the chart line, the verdict logic, the
    trace note, the verdict-summary text — must call THIS function and use
    its `threshold` value; there is no second copy of this computation
    anywhere in the module.

    Two necessary conditions bound g from above; we report both caps, which
    one binds, and every input that went into them, rather than asserting
    an unexplained q/4.

    Two modelling choices are made explicit here, stated (not hidden) so
    the resulting number stays auditable, chosen on cryptographic grounds
    BEFORE looking at any verdict (PATCH 02 §A.3) — never tuned to produce
    a break:

    - `C` (smoothing constant, `params.usability_C`, default 0.2): the
      textbook GPV/ABB bound's asymptotic omega(sqrt(log m)) factor hides a
      security-proof-grade constant. Taken literally as C=1 at these tiny
      demo parameters, sampling_cap ~= sigma/sqrt(log m) ~= 1.93 — smaller
      than even a freshly-generated TrapGen root basis's OWN claimed norm
      (the paper's Lemma 1: O(sqrt(n log q)) ~ 6 at these parameters), which
      would call the scheme unusable before KeyExt is ever invoked — a
      degenerate, uninformative threshold. We use `usability_C=0.2` (~5x
      more lenient) specifically so a fresh root trapdoor clears the bar,
      the minimum needed for "the chain later becomes unusable" to be a
      meaningful statement at all. Both the C=0.2 and the literal C=1
      numbers are reported below (`sampling_cap` vs `sampling_cap_C1_naive`)
      so this deviation is fully visible, not hidden.
    - The decode bound's noise width uses the ACTUAL PEKS/Trapdoor
      ciphertext noise (`params.ciphertext_noise_sigma`, default 0.4) rather
      than the lattice-sampling `params.sigma` (4.0) — those are two
      different widths in this codebase (params.sigma governs Klein/
      SamplePre's lattice-sampling quality; ciphertext_noise_sigma is the
      noise actually added to CT1/CT2/Trap's inner product in Verify), and
      the decode margin is governed by the latter. The literal decode_cap
      using params.sigma is also reported (`decode_cap_sigma_naive`) for
      the same transparency reason.
    """
    C = params.usability_C
    m, sigma, q = params.m, params.sigma, params.q
    decode_noise_sigma = params.ciphertext_noise_sigma
    log_m = max(math.log(m), 1.0)

    # Sampling bound: SamplePre/Klein needs sigma >= g * omega(sqrt(log m))
    # (GPV/ABB smoothing condition), i.e. g <= sigma / (C * sqrt(log m)).
    sampling_cap = sigma / (C * math.sqrt(log_m))
    # Decode bound: a basis of GS-norm g induces preimages of norm
    # ~ g * (decode noise) * sqrt(m); Verify's accumulated noise must stay
    # under q/4.
    decode_cap = (q / 4.0) / (decode_noise_sigma * math.sqrt(m))

    cap = min(sampling_cap, decode_cap)
    binding = "sampling" if sampling_cap <= decode_cap else "decode"

    # Transparency-only comparisons: what the LITERAL textbook formula
    # (C=1, decode noise = params.sigma) would have given. Never used for
    # the actual threshold — reported so the deviation is auditable.
    sampling_cap_C1_naive = sigma / (1.0 * math.sqrt(log_m))
    decode_cap_sigma_naive = (q / 4.0) / (sigma * math.sqrt(m))

    return {
        "threshold": cap,
        "binding_bound": binding,
        "sampling_cap": sampling_cap,
        "decode_cap": decode_cap,
        "C": C,
        "m": m,
        "sigma": sigma,
        "q": q,
        "log_m": log_m,
        "decode_noise_sigma": decode_noise_sigma,
        "sampling_cap_C1_naive": sampling_cap_C1_naive,
        "decode_cap_sigma_naive": decode_cap_sigma_naive,
        "threshold_C1_sigma_naive": min(sampling_cap_C1_naive, decode_cap_sigma_naive),
        "note": f"threshold={cap:.4f} (binding: {binding}; C={C}, m={m}, sigma={sigma}, q={q}). "
                f"Two explicit modelling choices behind this number: C={C} (not the literal "
                f"textbook C=1, which gives sampling_cap={sampling_cap_C1_naive:.3f} — strict "
                f"enough to reject a freshly-generated TrapGen root basis); and the decode bound "
                f"uses the actual ciphertext noise width {decode_noise_sigma} (not "
                f"params.sigma={sigma}, which would give decode_cap={decode_cap_sigma_naive:.3f}). "
                f"Both naive values are reported alongside the chosen ones for full auditability.",
    }


def _uniform_invertible(pk: np.ndarray, j: int, params: Params, seed: int) -> tuple[np.ndarray, np.ndarray]:
    """A 'naive' H1 alternative: a UNIFORMLY random invertible m x m matrix
    mod q — invertible (like the real H1), but with no norm bound at all.
    Deterministic in (pk, j) via a seeded RNG, for a fair side-by-side
    comparison against the real, low-norm H1.
    """
    m, q = params.m, params.q
    rng = random.Random(seed)
    for _ in range(50):
        cand = np.array([[rng.randrange(q) for _ in range(m)] for _ in range(m)], dtype=np.int64)
        try:
            inv = mat_inv_mod(cand, q)
            return cand, inv
        except Exception:
            continue
    raise RuntimeError("could not sample a uniformly random invertible matrix mod q")


def sigma_for_params(root_sk: np.ndarray, params: Params, safety: float = 1.2) -> float:
    """Dimension-aware sigma (PATCH 03 Lever 1). SamplePre/NewBasisDel's
    correctness condition is sigma >= ||T~|| * omega(sqrt(log m)) — a FIXED
    sigma silently violates this once the root basis's own Gram-Schmidt norm
    grows with m, which is exactly the scaling-sweep confound (PATCH 02
    §B/PATCH 03 diagnosis): the legit chain outruns a fixed threshold before
    any attack is considered. This is not a knob tuned to produce a nicer
    result — sigma is REQUIRED to scale with basis quality; a fixed sigma
    was the bug. `usability_threshold` already depends on sigma, so once
    sigma scales, the threshold rises with it on the same theoretical
    grounds, not by hand.
    """
    g = gram_schmidt_norm(centered_mod_q(root_sk, params.q))
    return safety * g * math.sqrt(max(math.log(params.m), 1.0))


def _build_chain(
    J: int, params: Params, rng: np.random.Generator, pyrng: random.Random,
    h1_variant: str, threshold: float, trace: Trace,
    root: tuple[np.ndarray, np.ndarray] | None = None,
    strengthen_legit: bool = False,
) -> tuple[list[dict], list[np.ndarray], list[np.ndarray], int | None]:
    """Builds the key-evolution chain AND judges the LEGITIMATE basis at
    every period against `threshold` (PATCH 01 §3) — before ever asking
    whether an attacker can do anything, we ask whether the scheme itself
    still works. `correctness_lost_at` is the first period where it doesn't.

    `root`, if given, is a pre-built (pk0, sk0) pair to use instead of
    calling trapgen again — needed by the scaling sweep (PATCH 03 Lever 1),
    which must measure the root basis's OWN quality before it can pick a
    dimension-aware sigma to build the rest of the chain with.

    `strengthen_legit` (PATCH 03 Lever 2, off by default — only the scaling
    sweep turns it on): re-reduces the root basis AND every NewBasisDel
    output with `linalg.strong_reduce` before it's measured or handed to
    the next period. This is legitimate — an honest key holder is entitled
    to use the best basis they can compute — and is kept structurally
    separate from the attacker's own LLL step in `_recover_candidate`,
    which is never touched by this flag.
    """
    q = params.q
    pk0, sk0 = root if root is not None else trapgen(params, rng, trace)
    strong_method = None
    if strengthen_legit:
        sk0, strong_method = strong_reduce(sk0)
        assert bool(np.all(mat_mod_mixed(pk0, sk0, q) == 0)), "strong_reduce left L_perp_q(pk0)"
    root_gs = gram_schmidt_norm(centered_mod_q(sk0, q))
    chain = [{
        "j": 0, "pk": pk0, "sk": sk0,
        "legit_gs": root_gs, "legit_usable": bool(root_gs <= threshold),
    }]
    correctness_lost_at = None if chain[0]["legit_usable"] else 0

    Rs: list[np.ndarray] = []
    R_invs: list[np.ndarray] = []
    pk, sk = pk0, sk0
    for j in range(1, J + 1):
        if h1_variant == "low_norm":
            R = H1(pk, j, params)
            # H1_inverse's exact (pre-reduction) values can be `object`
            # dtype; once reduced mod q every entry is small, so normalize
            # back to int64 to avoid a mixed int64/object matmul below.
            R_inv = np.array([[int(x) for x in row] for row in (H1_inverse(R) % q)], dtype=np.int64)
        elif h1_variant == "naive_uniform":
            R, R_inv = _uniform_invertible(pk, j, params, seed=hash((tuple(pk.flatten().tolist()), j)) & 0xFFFFFFFF)
        else:
            raise ValueError(f"unknown h1_variant {h1_variant!r}")

        pk_new = (pk @ R_inv) % q
        sk_new = new_basis_del(pk, R, sk, params.sigma, q, pyrng, R_inv=R_inv)
        if strengthen_legit:
            sk_new, strong_method = strong_reduce(sk_new)
        valid = bool(np.all(mat_mod_mixed(pk_new, sk_new, q) == 0))

        # Balanced representative BEFORE measuring — left in [0, q) (or
        # worse, un-reduced), the norm is inflated by the same
        # representative artifact Finding 2's candidate measurement had.
        legit_gs = gram_schmidt_norm(centered_mod_q(sk_new, q))
        legit_usable = bool(legit_gs <= threshold)
        if not legit_usable and correctness_lost_at is None:
            correctness_lost_at = j

        chain.append({
            "j": j, "pk": pk_new, "sk": sk_new, "valid": valid,
            "legit_gs": legit_gs, "legit_usable": legit_usable,
        })
        trace.compute(
            f"KeyExt period {j} ({h1_variant})",
            data={
                "R_col_norm": matrix_col_norm(R),
                "legit_gram_schmidt_norm_balanced": legit_gs,
                "legit_usable": legit_usable,
                "pk_sk_valid_mod_q": valid,
            },
            algo="ForwardSec",
        )
        Rs.append(R)
        R_invs.append(R_inv)
        pk, sk = pk_new, sk_new

    return chain, Rs, R_invs, correctness_lost_at, strong_method


def _verdict_for_period(legit_usable: bool, in_lattice: bool, trivial_gs: float, lll_gs: float, threshold: float) -> str:
    if not in_lattice:
        return "candidate not in lattice (bug — investigate)"
    if not legit_usable:
        # The legitimate chain already broke here: forward security is
        # undefined/moot at this period, and reporting "survives" would be
        # comparing the attacker against a basis nobody could use either.
        return "correctness lost (legit basis unusable)"
    if trivial_gs <= threshold:
        return "BROKEN (trivial transform)"
    if lll_gs <= threshold:
        return "BROKEN (after LLL reduction)"
    return "survives (trivial + LLL) at these params"


def _lll_reducer(basis: np.ndarray) -> tuple[np.ndarray, str]:
    """The attacker's default reduction — plain LLL(delta=0.75) — wrapped to
    the same (basis) -> (reduced, method_name) shape as `linalg.strong_reduce`,
    so both can be passed interchangeably as a `reducer` (PATCH 04)."""
    return lll_reduce(basis), "lll_delta_0.75"


def _recover_candidate(
    P_inv_centered: np.ndarray, target: np.ndarray, pk_i: np.ndarray, q: int,
    reducer=None,
) -> tuple[np.ndarray, np.ndarray, bool, float, float, str]:
    """The shared "attacker's move" (used by the main experiment and both
    scaling sweeps): balance the raw transform, then reduce it, and measure
    both. Returns (cand_trivial, cand_reduced, reduced_membership_ok,
    trivial_norm, reduced_norm, reducer_method).

    `reducer` defaults to plain LLL(delta=0.75) — the original, deliberately
    weaker attacker tooling. PATCH 04 passes `linalg.strong_reduce` here
    (the SAME function used to strengthen the legitimate chain) to close the
    "defender got BKZ, attacker only got LLL" asymmetry: pass the identical
    reducer to both sides and there is exactly one reduction strength in
    play, not two.
    """
    if reducer is None:
        reducer = _lll_reducer
    cand_raw = safe_matmul(P_inv_centered, target)  # exact integer product; membership holds mod q regardless of representative
    cand_trivial = centered_mod_q(cand_raw, q)
    trivial_ok = bool(np.all(mat_mod_mixed(pk_i, cand_trivial, q) == 0))
    if not trivial_ok:
        # This is the UNCONDITIONAL algebraic identity — it cannot fail.
        raise RuntimeError("ForwardSec: cand_trivial left L_perp_q(pk_i); this should never happen")
    trivial_norm = gram_schmidt_norm(cand_trivial)

    cand_reduced, method = reducer(cand_trivial)
    reduced_ok = bool(np.all(mat_mod_mixed(pk_i, cand_reduced, q) == 0))
    reduced_norm = gram_schmidt_norm(cand_reduced)
    return cand_trivial, cand_reduced, reduced_ok, trivial_norm, reduced_norm, method


def _suffix_products(R_invs: list[np.ndarray], J: int, m: int, q: int) -> list[np.ndarray]:
    """suffix[i] = R_{i+1}^-1 . R_{i+2}^-1 ... R_J^-1 (mod q), for i=0..J.
    suffix[J] = I. Built once, O(J)."""
    suffix = [None] * (J + 1)
    suffix[J] = np.eye(m, dtype=np.int64)
    for i in range(J - 1, -1, -1):
        suffix[i] = (R_invs[i] @ suffix[i + 1]) % q
    return suffix


def forward_sec_experiment(J: int, params: Params, seed: int = 0, h1_variant: str = "low_norm") -> dict:
    if h1_variant not in H1_VARIANTS:
        raise ValueError(f"h1_variant must be one of {H1_VARIANTS}")
    q, m = params.q, params.m
    trace = Trace()

    thr_info = usability_threshold(params)
    threshold = thr_info["threshold"]
    trace.note(
        "Explicit usability threshold (not an unexplained q/4)",
        detail=f"A basis is usable for SamplePre at sigma={params.sigma} only if its "
               f"Gram-Schmidt norm stays under BOTH the sampling bound and the decode "
               f"bound; the binding one here is the {thr_info['binding_bound']} bound.",
        data=thr_info,
        algo="ForwardSec",
        highlight=True,
    )
    trace.note(
        "Reduction: forward security reduces to a norm question",
        detail="pk_rJ = pk_ri . P^-1 (mod q) for P = R_J...R_{i+1}, so "
               "(pk_ri . P^-1) . sk_rJ = pk_rJ . sk_rJ = 0 (mod q) UNCONDITIONALLY — "
               "P^-1.sk_rJ is always a valid candidate basis of L_perp_q(pk_ri), "
               "computable from public data plus one stolen sk_rJ.",
        algo="ForwardSec",
        highlight=True,
    )

    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)
    chain, Rs, R_invs, correctness_lost_at, _strong_method = _build_chain(J, params, rng, pyrng, h1_variant, threshold, trace)

    trace.threat_model(
        f"Attacker steals sk_r{J} (only the CURRENT period's trapdoor)",
        detail="Models a device compromise, insider, or key-exfiltration event "
               "at the current period only — the scenario forward security is "
               "supposed to protect against for every EARLIER period.",
        algo="ForwardSec",
        highlight=True,
    )

    target = chain[J]["sk"]
    suffix = _suffix_products(R_invs, J, m, q)

    rows = []
    broken_trivial, broken_after_lll, survives, correctness_lost_rows = [], [], [], []
    for i in range(J):
        P_inv_centered = centered_mod_q(suffix[i], q)
        _cand_trivial, _cand_lll, lll_ok, trivial_norm, lll_norm, _method = _recover_candidate(
            P_inv_centered, target, chain[i]["pk"], q,
        )

        legit_gs = chain[i]["legit_gs"]
        legit_usable = chain[i]["legit_usable"]
        verdict = _verdict_for_period(legit_usable, lll_ok, trivial_norm, lll_norm, threshold)

        if verdict == "BROKEN (trivial transform)":
            broken_trivial.append(i)
        elif verdict == "BROKEN (after LLL reduction)":
            broken_after_lll.append(i)
        elif verdict.startswith("survives"):
            survives.append(i)
        elif verdict.startswith("correctness lost"):
            correctness_lost_rows.append(i)

        rows.append({
            "period": i,
            "periods_back": J - i,
            "legit_gram_schmidt_norm": legit_gs,
            "legit_usable": legit_usable,
            "candidate_trivial_gram_schmidt_norm": trivial_norm,
            "candidate_after_lll_gram_schmidt_norm": lll_norm,
            "usability_threshold": threshold,
            "membership_ok": lll_ok,
            "verdict": verdict,
        })
        trace.decision(
            f"Period {i} ({J - i} period(s) back from the stolen key)",
            verdict=verdict,
            evidence={
                "legit_gram_schmidt_norm": legit_gs,
                "legit_usable": legit_usable,
                "candidate_trivial_gram_schmidt_norm": trivial_norm,
                "candidate_after_lll_gram_schmidt_norm": lll_norm,
                "usability_threshold": threshold,
                "membership_ok": lll_ok,
            },
            detail="Verdict is gated on the LEGITIMATE basis being usable first — "
                   "if it isn't, comparing an attacker's candidate against it is moot.",
            algo="ForwardSec",
        )

    any_broken = bool(broken_trivial or broken_after_lll)

    summary = {
        "variant": h1_variant,
        "correctness_lost_at": correctness_lost_at,
        "broken_periods_trivial": broken_trivial,
        "broken_periods_after_lll": broken_after_lll,
        "survives_periods": survives,
        "correctness_lost_periods": correctness_lost_rows,
        "threshold": threshold,
        "binding_bound": thr_info["binding_bound"],
    }

    if correctness_lost_at is not None:
        headline = "Correctness collapse (KeyExt diverges) — forward security is moot"
        conclusion = (
            f"naive_uniform H1 -> correctness collapses at period {correctness_lost_at}; "
            f"the legitimate chain's own basis is no longer usable from that period on, "
            f"so the scheme is non-viable there and forward security cannot even be posed "
            f"as a question for {J - correctness_lost_at} of {J} tested period(s)."
        )
    elif any_broken:
        headline = "Forward-security weakness (LLL recovers recent periods)"
        conclusion = (
            f"low_norm H1 (required for correctness) keeps the legitimate chain usable "
            f"for all {J} periods, but the trivial R^-1 transform alone fails "
            f"(candidate norm > threshold) while LLL re-reduction recovers a USABLE "
            f"earlier basis for period(s) {broken_after_lll or broken_trivial} at n={params.n}."
        )
    else:
        headline = "Survives this reduction at these parameters"
        conclusion = (
            "The legitimate chain stays usable for every tested period, and neither the "
            "trivial candidate nor its LLL re-reduction drops under the usability "
            "threshold — inconclusive about forward security in general; only this "
            "specific reduction was tested."
        )

    scaling_caveat = SCALING_CAVEAT.format(n=params.n) if any_broken else None
    if scaling_caveat:
        trace.note(
            "Parameter-scaling caveat",
            detail=scaling_caveat,
            data={"n": params.n},
            algo="ForwardSec",
            highlight=True,
        )

    trace.result(
        f"Forward-security experiment verdict ({h1_variant}): {headline}",
        detail=conclusion,
        data={"summary": summary},
        algo="ForwardSec",
        highlight=True,
    )

    return {
        "h1_variant": h1_variant,
        "J": J,
        "rows": rows,
        "summary": summary,
        "headline": headline,
        "conclusion": conclusion,
        "correctness_lost_at": correctness_lost_at,
        "any_broken": any_broken,
        "scaling_caveat": scaling_caveat,
        "threshold_info": thr_info,
        "trace": trace.to_list(),
    }


# --------------------------------------------------------------------------
# PATCH 02 Task B — dimension-scaling sweep
# --------------------------------------------------------------------------
#
# Does the low_norm LLL break survive as n grows, or is it a low-dimension
# artifact? We measured (not guessed) the actual cost of a chain-build step
# before picking defaults here: new_basis_del takes ~2.8s at n=4 (m=72),
# ~12s at n=6 (m=108), ~38s at n=8 (m=144) on this machine — because m
# roughly doubles from n=4 to n=8 (m = 2n*ceil(log2 q)), and our from-
# scratch NewBasisDel (candidate resampling + exact independence tracking +
# LLL) scales worse than linearly in m. That is slower than the "n=8 stays
# fast" the patch anticipated, so this sweep enforces an explicit wall-clock
# budget and reports (never hangs) if it has to stop early.
#
# PATCH 03 — the scaling confound and its resolution:
# At a FIXED sigma, the legit basis's own Gram-Schmidt norm grows with m
# while the usability threshold's sampling bound only rises as ~1/sqrt(log
# m) — so the legitimate chain itself can lose usability BEFORE any attack
# is considered, contaminating `#broken -> 0` at larger n into meaning
# "nothing left to break" rather than "the break gets harder". Fixed by,
# in order (never jumping ahead; each was checked before moving on):
#   Lever 1 (sigma_for_params): sigma is REQUIRED to scale with the root
#     basis's measured quality (sigma >= ||T~|| * omega(sqrt(log m))) — a
#     fixed sigma was the bug, not a knob. This alone fixed n=4 and n=6 but
#     n=8 still lost usability (the decode bound, which does not depend on
#     sigma, became binding and insufficient there).
#   Lever 2 (strong_reduce): re-reduces the LEGIT basis (root AND every
#     NewBasisDel output, never the attacker's own recovery) with fpylll's
#     BKZ if installed, else our own LLL at delta=0.99. Combined with Lever
#     1, this keeps the legitimate chain usable across n=4,6,8 (confirmed:
#     correctness_lost_at is None at every tested n).
# We did not need Lever 3 (a proper gadget trapdoor) or the fallback.
#
# A genuinely interesting side effect of Lever 2, reported plainly rather
# than smoothed over: strengthening the legitimate chain's OWN stored basis
# (what actually gets "stolen" as sk_rJ) changes what the attacker's
# transform is applied to. With real BKZ available, this closes even the
# n=4 break the single-experiment tab (forward_sec_experiment, which does
# NOT apply Lever 2) still shows. That is not a contradiction between the
# two: it demonstrates that part of the practical break is an artifact of
# NOT re-reducing one's own delegated basis, i.e. basis hygiene (periodic
# strong reduction of your own stored trapdoor) is a real, honest
# mitigation — it does not remove the underlying structural fact (a public,
# low-norm-invertible R has a computable, if large, inverse), which is the
# single-experiment tab's finding and is unaffected by this sweep.

DEFAULT_SWEEP_N_VALUES = (4, 6, 8)
DEFAULT_SWEEP_TIME_BUDGET_S = 240.0


def scaling_sweep(
    J: int, base_params: Params, n_values: tuple[int, ...] = DEFAULT_SWEEP_N_VALUES,
    seed: int = 0, time_budget_s: float = DEFAULT_SWEEP_TIME_BUDGET_S,
) -> dict:
    """Runs the low_norm forward-security reduction at each n in `n_values`
    (m re-derived per n; a fresh Params, not a partial copy — m must not be
    carried over from a different n), measuring how many of the J-1 earlier
    periods fall below the (SAME, audited — PATCH 02 §B.2) usability
    threshold after LLL.
    """
    import time

    rows: list[dict] = []
    start = time.time()
    for n in n_values:
        elapsed = time.time() - start
        if elapsed >= time_budget_s:
            rows.append({
                "n": n, "skipped": True,
                "note": f"sweep time budget ({time_budget_s:.0f}s) exceeded after "
                        f"{elapsed:.1f}s; skipping n={n} and any larger n rather than hanging.",
            })
            break

        p = Params(n=n, q=base_params.q, sigma=base_params.sigma, l=base_params.l,
                   usability_C=base_params.usability_C, m=0)
        problems = p.validate()
        if problems:
            rows.append({"n": n, "m": p.m, "error": "; ".join(problems)})
            continue

        t0 = time.time()
        rng = np.random.default_rng(seed)
        pyrng = random.Random(seed)

        # PATCH 03 Lever 1: build the root FIRST, measure its own quality,
        # then pick sigma from THAT — not a fixed sigma held over from n=4.
        # This is what keeps the legit chain usable across n; see
        # sigma_for_params's docstring for why this isn't a tuned knob.
        pk0, sk0 = trapgen(p, rng)
        p.sigma = sigma_for_params(sk0, p)

        thr_info = usability_threshold(p)
        threshold = thr_info["threshold"]
        throwaway_trace = Trace()
        # PATCH 03 Lever 2: also re-reduce the legit chain with the
        # strongest reduction available (fpylll BKZ if installed, else our
        # own LLL at delta=0.99) — applied unconditionally alongside Lever 1
        # rather than only for dimensions where Lever 1 alone falls short,
        # since it only ever improves (never worsens) the legit basis.
        chain, _Rs, R_invs, correctness_lost_at, strong_method = _build_chain(
            J, p, rng, pyrng, "low_norm", threshold, throwaway_trace, root=(pk0, sk0),
            strengthen_legit=True,
        )

        target = chain[J]["sk"]
        suffix = _suffix_products(R_invs, J, p.m, p.q)

        broken = []
        for i in range(J):
            P_inv_centered = centered_mod_q(suffix[i], p.q)
            _t, _l, lll_ok, _trivial_norm, lll_norm, _method = _recover_candidate(
                P_inv_centered, target, chain[i]["pk"], p.q,
            )
            if chain[i]["legit_usable"] and lll_ok and lll_norm <= threshold:
                broken.append({"period": i, "periods_back": J - i, "after_lll_gs": lll_norm})

        runtime_s = time.time() - t0
        rows.append({
            "n": n,
            "m": p.m,
            "sigma": p.sigma,
            "threshold": threshold,
            "root_legit_gs": chain[0]["legit_gs"],
            "max_legit_gs": max(entry["legit_gs"] for entry in chain),
            "legit_reduction_method": strong_method,
            "correctness_lost_at": correctness_lost_at,
            "num_broken": len(broken),
            "broken": broken,
            "min_after_lll": min((b["after_lll_gs"] for b in broken), default=None),
            "runtime_s": runtime_s,
        })

    measured = [r for r in rows if "error" not in r and not r.get("skipped")]
    nums = [r["num_broken"] for r in measured]

    if len(nums) < 2:
        trend = "inconclusive"
        trend_text = "Fewer than two dimensions completed within the time budget; no trend can be reported."
    elif all(x == 0 for x in nums):
        trend = "never_broken"
        trend_text = (
            "Zero periods broke at EVERY tested dimension, including n=4 — with the "
            "legitimate chain's own basis kept at its best achievable quality (PATCH 03 "
            "Levers 1+2), the trivial-transform-plus-LLL attack does not recover a usable "
            "earlier basis even at the smallest dimension tested. This is a stronger, more "
            "positive result than 'shrinks with n': it did not break here at all."
        )
    elif all(a >= b for a, b in zip(nums, nums[1:])) and nums[0] > nums[-1]:
        trend = "shrinking"
        trend_text = (
            "Break shrinks with dimension — consistent with a low-dimension (LLL) "
            "artifact; forward security likely holds at secure parameters. Reported honestly."
        )
    elif nums[-1] >= nums[0] and nums[-1] > 0:
        trend = "flat_or_growing"
        trend_text = (
            "Break persists (or grows) across tested dimensions even with the legitimate "
            "chain's own basis kept at its best achievable quality — stronger evidence of "
            "a structural forward-security weakness. The ATTACKER's own recovery here still "
            "only uses plain LLL (delta=0.75), not BKZ; confirming this persists at "
            "cryptographic n would additionally need a BKZ-equipped attacker, which this "
            "lab does not run."
        )
    else:
        trend = "mixed"
        trend_text = "The trend across tested dimensions is not monotone; reported as measured, not summarized further."

    # Confound check: `num_broken` is only a clean "does the LLL break shrink
    # with n" measurement when the LEGITIMATE chain itself stayed healthy —
    # at fixed sigma, our own TrapGen+LLL construction's root-basis quality
    # degrades as n (hence m) grows, since the sampling-bound threshold
    # shrinks (~1/sqrt(log m)) while the achieved root norm tends to grow
    # with m — so at large enough n the scheme can go unusable independent
    # of any attack, and a shrinking `num_broken` there partly reflects
    # "there's nothing left to break", not "the break gets harder". This is
    # NOT swept under the rug: it's checked and reported explicitly.
    unhealthy_ns = [r["n"] for r in measured if r["correctness_lost_at"] is not None]
    confound_note = None
    if unhealthy_ns:
        confound_note = (
            f"Confound NOT fully resolved: at n={unhealthy_ns}, the LEGITIMATE chain "
            f"itself lost usability before any attack was considered, even with "
            f"dimension-aware sigma (PATCH 03 Lever 1) and strengthened basis reduction "
            f"(Lever 2, method={[r['legit_reduction_method'] for r in measured if r['n'] in unhealthy_ns]}). "
            f"A shrinking num_broken at those n partly reflects 'nothing usable left to "
            f"break', not necessarily 'the break gets harder'. Read the trend alongside "
            f"correctness_lost_at per row."
        )

    any_break_anywhere = any(n > 0 for n in nums)
    methods_used = sorted({r["legit_reduction_method"] for r in measured})
    confound_resolved = bool(measured) and not unhealthy_ns
    if not measured:
        resolution_summary = "No dimension completed within the time budget."
    elif confound_resolved:
        lever = "Lever 1 (dimension-aware sigma) alone" if len(n_values) <= 1 else (
            "Levers 1+2 (dimension-aware sigma + strengthened legit-basis reduction)"
        )
        resolution_summary = (
            f"Scaling confound RESOLVED via {lever} — the legitimate chain stayed usable "
            f"(correctness_lost_at is None) at every tested n. Legit-basis reduction method: "
            f"{', '.join(methods_used)}. num_broken is therefore a trustworthy measurement "
            f"of attack difficulty, not an artifact of the legit chain breaking first."
        )
    else:
        resolution_summary = (
            f"Scaling confound NOT fully resolved at n={unhealthy_ns} even after Levers 1+2 "
            f"(method: {', '.join(methods_used)}) — see confound_note. Per PATCH 03 §4, this "
            f"is reported as the honest fallback rather than disguised as a clean trend."
        )

    return {
        "J": J,
        "n_values": list(n_values),
        "rows": rows,
        "trend": trend,
        "trend_text": trend_text,
        "confound_note": confound_note,
        "confound_resolved": confound_resolved,
        "resolution_summary": resolution_summary,
        "scaling_caveat": SCALING_CAVEAT.format(n=max((r["n"] for r in measured), default=n_values[0])) if any_break_anywhere else None,
    }


# --------------------------------------------------------------------------
# PATCH 04 — symmetric tooling: give the attacker the SAME reducer strength
# as the defender, and show the fairness matrix explicitly.
# --------------------------------------------------------------------------
#
# After PATCH 03, the legitimate chain is strengthened with BKZ/strong LLL
# but the attacker's recovered candidate was still only ever plain LLL — a
# "defender got BKZ, attacker only got LLL" asymmetry that would undercut
# any no-break result. Three configs make the fairness explicit:
#   LLL_vs_LLL        — legit basis: plain LLL.  attacker: plain LLL.
#   BKZ_defender_only — legit basis: strong_reduce.  attacker: plain LLL.  (PATCH 03's sweep)
#   BKZ_vs_BKZ        — legit basis: strong_reduce.  attacker: strong_reduce (SAME reducer).
#
# LLL_vs_LLL and {BKZ_defender_only, BKZ_vs_BKZ} need genuinely SEPARATE
# chain builds: once one period's legit basis is (or isn't) strengthened,
# that changes what NewBasisDel receives as T_A for the NEXT period, so the
# two chains diverge after period 1 — there is no way to compute both from
# a single set of NewBasisDel calls. BKZ_defender_only and BKZ_vs_BKZ DO
# share one chain build (they only differ in the attacker's own reducer, a
# cheap post-hoc step), so this only costs 2x a single-config sweep, not 3x.
#
# The BKZ_vs_BKZ row is the authoritative fairness test (PATCH 04 §3) — the
# other two are shown for context, never averaged or cherry-picked from.

THREE_WAY_CONFIGS = ("LLL_vs_LLL", "BKZ_defender_only", "BKZ_vs_BKZ")
DEFAULT_THREE_WAY_N_VALUES = (4, 6)
DEFAULT_THREE_WAY_TIME_BUDGET_S = 400.0


def three_way_reduction_sweep(
    J: int, base_params: Params, n_values: tuple[int, ...] = DEFAULT_THREE_WAY_N_VALUES,
    seed: int = 0, time_budget_s: float = DEFAULT_THREE_WAY_TIME_BUDGET_S,
) -> dict:
    """Runs all three LLL/BKZ configs (PATCH 04 §2) at each n, using the SAME
    audited threshold (PATCH 02 §A.2) throughout. Slower than the plain
    scaling sweep (two full chain builds per n instead of one) — n defaults
    to {4, 6} rather than {4, 6, 8} given the measured n=8 cost (PATCH 03:
    ~150s for one chain build), bounded by an explicit time budget either way.
    """
    import time

    rows: list[dict] = []
    start = time.time()
    for n in n_values:
        elapsed = time.time() - start
        if elapsed >= time_budget_s:
            rows.append({
                "n": n, "config": None, "skipped": True,
                "note": f"sweep time budget ({time_budget_s:.0f}s) exceeded after "
                        f"{elapsed:.1f}s; skipping n={n} and any larger n rather than hanging.",
            })
            break

        p = Params(n=n, q=base_params.q, sigma=base_params.sigma, l=base_params.l,
                   usability_C=base_params.usability_C, m=0)
        problems = p.validate()
        if problems:
            rows.append({"n": n, "config": None, "error": "; ".join(problems)})
            continue

        # Lever 1: one root, shared by both chain builds below, sets sigma
        # (hence the threshold) identically for every config at this n.
        rng_root = np.random.default_rng(seed)
        pk0, sk0 = trapgen(p, rng_root)
        p.sigma = sigma_for_params(sk0, p)
        thr_info = usability_threshold(p)
        threshold = thr_info["threshold"]

        # Two genuinely separate chain builds (see module note above).
        t_plain0 = time.time()
        chain_plain, _Rs_p, R_invs_plain, cla_plain, method_plain = _build_chain(
            J, p, np.random.default_rng(seed), random.Random(seed), "low_norm", threshold,
            Trace(), root=(pk0, sk0), strengthen_legit=False,
        )
        t_plain = time.time() - t_plain0

        t_strong0 = time.time()
        chain_strong, _Rs_s, R_invs_strong, cla_strong, method_strong = _build_chain(
            J, p, np.random.default_rng(seed), random.Random(seed), "low_norm", threshold,
            Trace(), root=(pk0, sk0), strengthen_legit=True,
        )
        t_strong = time.time() - t_strong0

        config_sources = {
            "LLL_vs_LLL": (chain_plain, R_invs_plain, cla_plain, None, t_plain),
            "BKZ_defender_only": (chain_strong, R_invs_strong, cla_strong, None, t_strong),
            "BKZ_vs_BKZ": (chain_strong, R_invs_strong, cla_strong, strong_reduce, t_strong),
        }

        for config_name in THREE_WAY_CONFIGS:
            chain, R_invs, correctness_lost_at, attacker_reducer, build_time = config_sources[config_name]
            t0 = time.time()
            target = chain[J]["sk"]
            suffix = _suffix_products(R_invs, J, p.m, p.q)

            broken = []
            reducer_methods = set()
            for i in range(J):
                P_inv_centered = centered_mod_q(suffix[i], p.q)
                _t, _r, red_ok, _trivial_norm, reduced_norm, method = _recover_candidate(
                    P_inv_centered, target, chain[i]["pk"], p.q, reducer=attacker_reducer,
                )
                reducer_methods.add(method)
                if chain[i]["legit_usable"] and red_ok and reduced_norm <= threshold:
                    broken.append({"period": i, "periods_back": J - i, "after_reduction_gs": reduced_norm})

            rows.append({
                "n": n,
                "config": config_name,
                "m": p.m,
                "sigma": p.sigma,
                "threshold": threshold,
                "legit_reducer_method": (
                    "lll_construction_only"  # NewBasisDel's own internal LLL; no extra strengthening
                    if config_name == "LLL_vs_LLL" else method_strong
                ),
                "attacker_reducer_method": next(iter(reducer_methods)) if len(reducer_methods) == 1 else sorted(reducer_methods),
                "correctness_lost_at": correctness_lost_at,
                "num_broken": len(broken),
                "broken": broken,
                "min_after_reduction": min((b["after_reduction_gs"] for b in broken), default=None),
                "runtime_s": build_time + (time.time() - t0),
            })

    measured = [r for r in rows if "error" not in r and not r.get("skipped")]
    bkz_vs_bkz_rows = [r for r in measured if r["config"] == "BKZ_vs_BKZ"]

    if not bkz_vs_bkz_rows:
        verdict = "inconclusive"
        verdict_text = "No BKZ_vs_BKZ row completed within the time budget; no fairness verdict can be reported."
    elif all(r["num_broken"] == 0 and r["correctness_lost_at"] is None for r in bkz_vs_bkz_rows):
        verdict = "resists_symmetric_bkz"
        verdict_text = (
            "Forward-security mechanism resists the R^-1-transform attack even under "
            "symmetric BKZ tooling, at all tested dimensions. The attack does not recover "
            "a usable earlier basis. (Demo params; secure-parameter proof still open.)"
        )
    else:
        broken_ns = sorted({r["n"] for r in bkz_vs_bkz_rows if r["num_broken"] > 0})
        broken_periods = sorted({b["period"] for r in bkz_vs_bkz_rows if r["num_broken"] > 0 for b in r["broken"]})
        verdict = "broken_under_symmetric_bkz"
        verdict_text = (
            f"Under symmetric BKZ tooling the attack recovers a usable earlier basis for "
            f"period(s) {broken_periods} at n={broken_ns} — a forward-security break that "
            f"only appears once the attacker is given reduction strength equal to the "
            f"defender's. This was hidden by the earlier LLL-only attacker tooling."
        )

    return {
        "J": J,
        "n_values": list(n_values),
        "rows": rows,
        "verdict": verdict,
        "verdict_text": verdict_text,
        "caveats": [
            "Demonstration parameters (n <= 8). Even symmetric BKZ at small n does not "
            "settle the cryptographic-parameter question; that needs a proof or a "
            "large-n BKZ cost estimate, neither of which this lab performs.",
            "This tests ONE attack family (public R^-1 transform + lattice reduction). "
            "'Resists this attack' is not the same claim as 'provably forward-secure'.",
        ],
    }
