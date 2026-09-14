"""Finding 2 — forward-security norm experiment.

**Claim under test:** stealing the CURRENT period's trapdoor sk_rJ must not
reveal any EARLIER period's trapdoor sk_ri (i < J) — that's what "forward
security" means for a time-evolving key.

**Reduction:** consecutive periods are related by a PUBLIC low-norm
invertible transform R_j = H1(pk_r{j-1}, j): pk_rj = pk_r{j-1} . R_j^-1 (mod
q). Chaining periods i+1..J gives pk_rJ = pk_ri . P^-1 (mod q) where
P = R_J . R_{J-1} ... . R_{i+1}. Since pk_rJ . sk_rJ = 0 (mod q), the identity

    pk_ri . (P^-1 . sk_rJ) = (pk_ri . P^-1) . sk_rJ = pk_rJ . sk_rJ = 0 (mod q)

holds UNCONDITIONALLY — it doesn't matter how sk_rJ was produced (even our
re-randomizing NewBasisDel). So `cand_i = P^-1 . sk_rJ` is ALWAYS a valid
candidate basis of L_perp_q(pk_ri), computable from PUBLIC data (every pk_rj
and H1 are public) plus the one stolen sk_rJ. Forward security therefore
reduces entirely to a norm question: is cand_i short enough to actually WORK
as a trapdoor?

**R^-1 audit (over Z vs mod q):** each R_j = H1(...) = I + N has det = 1
EXACTLY over Z, so it has a genuine integer inverse (linalg.H1_inverse, via
back-substitution — no division ever needed). We build P^-1 by chaining the
mod-q reductions of those exact inverses one step at a time. That's
mathematically forced to agree with "multiply the exact-over-Z inverses
together first, reduce the product mod q once at the end" — mod-q reduction
is a ring homomorphism, so it doesn't matter when you apply it — and we
verified this by direct comparison (see test_forward_sec.py); the two
computations agree on every entry. There is no over-Z-vs-mod-q discrepancy
to fix here (for the naive-uniform comparison variant, "over Z" doesn't even
apply: a uniformly random matrix mod q has no reason to have determinant
+/-1 over Z, so it has no integer inverse at all — only a mod-q one).

**The artifact that DID need fixing — balanced representatives:** `cand_i`'s
entries only need to be correct MOD q (matrix-vector reduction mod q depends
only on residues), so any two representatives of the same residue describe
the identical lattice point. The raw product P^-1_centered @ sk_rJ, left
un-reduced, can have enormous entries with no cryptographic meaning — just
an artifact of which representative happened to fall out of the
multiplication. Every entry is remapped to (-q/2, q/2] (`centered_mod_q`)
before any norm is measured.

**The experiment that actually answers the question — LLL re-reduction:**
a balanced-but-unreduced cand_i is *some* valid basis of L_perp_q(pk_ri), not
necessarily a good one. The honest question is what the attacker gets after
doing the same thing our own NewBasisDel does: LLL-reduce it. So every
candidate is measured twice — trivially (balanced, no further work) and
after LLL — giving three possible, HONEST verdicts per period:
  - "BROKEN (trivial)"            — already short before any reduction.
  - "BROKEN (after LLL reduction)" — short only once LLL is applied.
  - "survives both"                — still not short even after LLL.

**Honesty requirement (CLAUDE.md §4, Finding 2):** every verdict below is
DERIVED from measured Gram-Schmidt norms, never hard-coded. We run this under
two H1 instantiations — the low-norm I+N construction (hashes.H1) and a
naive uniform-invertible one — to show the result depends on a distribution
the paper never specifies.
"""

from __future__ import annotations

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


def _build_chain(J: int, params: Params, rng: np.random.Generator, pyrng: random.Random,
                  h1_variant: str, trace: Trace) -> tuple[list[dict], list[np.ndarray], list[np.ndarray]]:
    q = params.q
    pk0, sk0 = trapgen(params, rng, trace)
    chain = [{"j": 0, "pk": pk0, "sk": sk0}]
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
        ok = bool(np.all(mat_mod_mixed(pk_new, sk_new, q) == 0))
        chain.append({"j": j, "pk": pk_new, "sk": sk_new, "valid": ok})
        trace.compute(
            f"KeyExt period {j} ({h1_variant})",
            data={
                "R_col_norm": matrix_col_norm(R),
                "sk_gram_schmidt_norm": gram_schmidt_norm(sk_new),
                "pk_sk_valid": ok,
            },
            algo="ForwardSec",
        )
        Rs.append(R)
        R_invs.append(R_inv)
        pk, sk = pk_new, sk_new
    return chain, Rs, R_invs


def forward_sec_experiment(J: int, params: Params, seed: int = 0, h1_variant: str = "low_norm") -> dict:
    if h1_variant not in H1_VARIANTS:
        raise ValueError(f"h1_variant must be one of {H1_VARIANTS}")
    q, m = params.q, params.m
    trace = Trace()
    trace.note(
        "Reduction: forward security reduces to a norm question",
        detail="pk_rJ = pk_ri . P^-1 (mod q) for P = R_J...R_{i+1}, so "
               "(pk_ri . P^-1) . sk_rJ = pk_rJ . sk_rJ = 0 (mod q) UNCONDITIONALLY — "
               "P^-1.sk_rJ is always a valid candidate basis of L_perp_q(pk_ri), "
               "computable from public data plus one stolen sk_rJ. The only open "
               "question is whether it's short enough to be USABLE.",
        algo="ForwardSec",
        highlight=True,
    )

    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)
    chain, Rs, R_invs = _build_chain(J, params, rng, pyrng, h1_variant, trace)

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

    usability_threshold = q // 4
    rows = []
    for i in range(J):
        P_inv_centered = centered_mod_q(suffix[i], q)
        cand_raw = safe_matmul(P_inv_centered, target)  # exact integer product; membership holds mod q regardless of representative

        # Balanced representative: entries only matter mod q, so remap every
        # one into (-q/2, q/2] before measuring anything — an un-reduced
        # entry is an artifact of the multiplication, not a real quantity.
        cand_trivial = centered_mod_q(cand_raw, q)
        trivial_ok = bool(np.all(mat_mod_mixed(chain[i]["pk"], cand_trivial, q) == 0))
        trivial_norm = gram_schmidt_norm(cand_trivial)

        # The actual question: what does the attacker get after doing the
        # same thing our own NewBasisDel does — LLL-reduce it?
        cand_lll = lll_reduce(cand_trivial)
        lll_ok = bool(np.all(mat_mod_mixed(chain[i]["pk"], cand_lll, q) == 0))
        lll_norm = gram_schmidt_norm(cand_lll)

        legit_norm = gram_schmidt_norm(chain[i]["sk"])
        membership_ok = trivial_ok and lll_ok

        if not membership_ok:
            verdict = "NOT IN LATTICE (unexpected)"
        elif trivial_norm < usability_threshold:
            verdict = "BROKEN (trivial)"
        elif lll_norm < usability_threshold:
            verdict = "BROKEN (after LLL reduction)"
        else:
            verdict = "survives both"

        rows.append({
            "period": i,
            "periods_back": J - i,
            "legit_gram_schmidt_norm": legit_norm,
            "candidate_trivial_gram_schmidt_norm": trivial_norm,
            "candidate_after_lll_gram_schmidt_norm": lll_norm,
            "usability_threshold": usability_threshold,
            "membership_ok": membership_ok,
            "verdict": verdict,
        })
        trace.decision(
            f"Period {i} ({J - i} period(s) back from the stolen key)",
            verdict=verdict,
            evidence={
                "legit_gram_schmidt_norm": legit_norm,
                "candidate_trivial_gram_schmidt_norm": trivial_norm,
                "candidate_after_lll_gram_schmidt_norm": lll_norm,
                "usability_threshold_q_over_4": usability_threshold,
                "membership_ok": membership_ok,
            },
            detail="Balanced representative measured first (trivial), then LLL-reduced and re-measured — the same finishing step NewBasisDel itself applies.",
            algo="ForwardSec",
        )

    any_broken = any(r["verdict"].startswith("BROKEN") for r in rows)
    overall = (
        "BROKEN: at least one earlier period's trapdoor is cheaply recoverable"
        if any_broken else
        "Earlier periods survive both the trivial candidate and its LLL "
        "re-reduction at these parameters (inconclusive about forward "
        "security in general — only this specific reduction was tested)."
    )
    trace.result(
        f"Forward-security experiment verdict ({h1_variant})",
        detail=overall,
        data={"any_period_broken": any_broken, "h1_variant": h1_variant},
        algo="ForwardSec",
        highlight=True,
    )

    return {
        "h1_variant": h1_variant,
        "J": J,
        "rows": rows,
        "any_period_broken": any_broken,
        "overall_verdict": overall,
        "trace": trace.to_list(),
    }
