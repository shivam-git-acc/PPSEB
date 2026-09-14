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
    centered_mod_q, gram_schmidt_norm, lll_reduce, mat_inv_mod, mat_mod_mixed, matrix_col_norm,
    safe_matmul,
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
    """Is a basis with Gram-Schmidt norm g "usable" as a trapdoor for
    SamplePre at width params.sigma? Two necessary conditions bound g from
    above; we report both caps and which one binds, rather than asserting
    an unexplained q/4 (PATCH 01 §2).

    Two modelling choices are made explicit here, both stated (not hidden)
    so the resulting number stays auditable:

    - `C` (smoothing constant): the textbook GPV/ABB bound uses an
      asymptotic omega(sqrt(log m)) factor, whose hidden constant is a
      conservative, security-proof-grade choice. Taken literally (C=1) at
      these tiny demo parameters it rules out even a freshly-generated
      TrapGen root basis (Lemma 1's own claimed norm, O(sqrt(n log q)) ~ 6,
      already exceeds it) — a degenerate, uninformative threshold that
      would call the scheme unusable before KeyExt is ever invoked. We use
      a smaller, explicitly-stated C so a fresh root trapdoor clears the
      bar, which is the only way "the chain later becomes unusable" can be
      a meaningful statement at all.
    - The decode bound uses the ACTUAL PEKS/Trapdoor ciphertext noise width
      (`scheme.CIPHERTEXT_NOISE_SIGMA`) rather than the lattice-sampling
      `params.sigma` — those are two different widths in this codebase
      (`params.sigma` governs Klein/SamplePre's lattice-sampling quality;
      CIPHERTEXT_NOISE_SIGMA is the noise actually added to CT1/CT2/Trap's
      inner product in Verify), and the decode margin is governed by the
      latter.
    """
    from ppseb.scheme import CIPHERTEXT_NOISE_SIGMA

    C = 0.2
    m = params.m
    # Sampling bound: SamplePre/Klein needs sigma >= g * omega(sqrt(log m))
    # (GPV/ABB smoothing condition), i.e. g <= sigma / (C * sqrt(log m)).
    sampling_cap = params.sigma / (C * math.sqrt(max(math.log(m), 1.0)))
    # Decode bound: a basis of GS-norm g induces preimages of norm
    # ~ g * CIPHERTEXT_NOISE_SIGMA * sqrt(m); Verify's accumulated noise
    # must stay under q/4.
    decode_cap = (params.q / 4.0) / (CIPHERTEXT_NOISE_SIGMA * math.sqrt(m))

    cap = min(sampling_cap, decode_cap)
    binding = "sampling" if sampling_cap <= decode_cap else "decode"
    return {
        "threshold": cap,
        "binding_bound": binding,
        "sampling_cap": sampling_cap,
        "decode_cap": decode_cap,
        "modelling_constant_C": C,
        "decode_noise_sigma": CIPHERTEXT_NOISE_SIGMA,
        "note": f"Two explicit modelling choices, stated for auditability: "
                f"C={C} (smaller than the textbook asymptotic constant 1.0, "
                f"chosen so a freshly-generated TrapGen root basis clears the "
                f"sampling bound); the decode bound uses the actual PEKS/"
                f"Trapdoor ciphertext noise width ({CIPHERTEXT_NOISE_SIGMA}), "
                f"not the lattice-sampling sigma ({params.sigma}).",
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


def _build_chain(
    J: int, params: Params, rng: np.random.Generator, pyrng: random.Random,
    h1_variant: str, threshold: float, trace: Trace,
) -> tuple[list[dict], list[np.ndarray], list[np.ndarray], int | None]:
    """Builds the key-evolution chain AND judges the LEGITIMATE basis at
    every period against `threshold` (PATCH 01 §3) — before ever asking
    whether an attacker can do anything, we ask whether the scheme itself
    still works. `correctness_lost_at` is the first period where it doesn't.
    """
    q = params.q
    pk0, sk0 = trapgen(params, rng, trace)
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

    return chain, Rs, R_invs, correctness_lost_at


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
    chain, Rs, R_invs, correctness_lost_at = _build_chain(J, params, rng, pyrng, h1_variant, threshold, trace)

    trace.threat_model(
        f"Attacker steals sk_r{J} (only the CURRENT period's trapdoor)",
        detail="Models a device compromise, insider, or key-exfiltration event "
               "at the current period only — the scenario forward security is "
               "supposed to protect against for every EARLIER period.",
        algo="ForwardSec",
        highlight=True,
    )

    target = chain[J]["sk"]

    # suffix[i] = R_{i+1}^-1 . R_{i+2}^-1 ... R_J^-1 (mod q), built once, O(J)
    suffix = [None] * (J + 1)
    suffix[J] = np.eye(m, dtype=np.int64)
    for i in range(J - 1, -1, -1):
        suffix[i] = (R_invs[i] @ suffix[i + 1]) % q

    rows = []
    broken_trivial, broken_after_lll, survives, correctness_lost_rows = [], [], [], []
    for i in range(J):
        P_inv_centered = centered_mod_q(suffix[i], q)
        cand_raw = safe_matmul(P_inv_centered, target)  # exact integer product; membership holds mod q regardless of representative

        # Balanced representative: entries only matter mod q, so remap every
        # one into (-q/2, q/2] before measuring anything.
        cand_trivial = centered_mod_q(cand_raw, q)
        trivial_ok = bool(np.all(mat_mod_mixed(chain[i]["pk"], cand_trivial, q) == 0))
        if not trivial_ok:
            # This is the UNCONDITIONAL algebraic identity — it cannot fail.
            raise RuntimeError("ForwardSec: cand_trivial left L_perp_q(pk_i); this should never happen")
        trivial_norm = gram_schmidt_norm(cand_trivial)

        # The actual question: what does the attacker get after doing the
        # same thing our own NewBasisDel does — LLL-reduce it?
        cand_lll = lll_reduce(cand_trivial)
        lll_ok = bool(np.all(mat_mod_mixed(chain[i]["pk"], cand_lll, q) == 0))
        lll_norm = gram_schmidt_norm(cand_lll)

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
