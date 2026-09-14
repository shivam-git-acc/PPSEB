"""Finding 3 — Algorithm 2 (KeyExt) is not executable as printed.

The paper's KeyExt has two circular dependencies:
  * Line 6: `R = H1(pk_rj, j)` — uses pk_rj, the public key THIS algorithm
    is supposed to produce.
  * Line 7: `sk_rj = NewBasisDel(pk_rj, R, sk_rj, sigma)` — uses sk_rj (and
    the just-as-undefined pk_rj) as an INPUT to the call that produces sk_rj.

This module transcribes those two lines literally, in the paper's own
variable names and order, and lets Python's own name-resolution rules
demonstrate the circularity (an `UnboundLocalError`: a name is referenced
before the assignment that the interpreter has already scheduled for it).
Then it runs the corrected single-step KeyExt (scheme.keyext) across a chain
of periods and verifies `pk_rj . sk_rj = 0 (mod q)` at every one.
"""

from __future__ import annotations

import random

import numpy as np

from ppseb.hashes import H1
from ppseb.linalg import gram_schmidt_norm, mat_mod_mixed
from ppseb.params import Params
from ppseb.samplers import new_basis_del
from ppseb.scheme import keyext
from ppseb.trace import Trace
from ppseb.trapgen import trapgen

PAPER_LINE_6 = "R = H1(pk_rj, j)"
PAPER_LINE_7 = "sk_rj = NewBasisDel(pk_rj, R, sk_rj, sigma)"

JUSTIFICATION = {
    "input_list": "Algorithm 2's own stated inputs are (j, pk_r{j-1}, sk_r{j-1}, params) — "
                  "pk_rj and sk_rj are not among them; they cannot be read before they exist.",
    "lemma_5_signature": "Lemma 5 defines NewBasisDel(A, R, T_A, sigma) as taking a SOURCE "
                          "basis T_A of an EXISTING lattice A and producing a basis of a "
                          "DIFFERENT lattice A.R^-1 — its whole point is delegating FROM a "
                          "basis you already have, not consuming its own output.",
    "algorithm_4_analogy": "The paper's own Algorithm 4 (Trapdoor) calls NewBasisDel(pk_rj, "
                            "beta, sk_rj, sigma) using the CURRENT period's already-established "
                            "pk_rj/sk_rj to derive a NEW keyword-specific basis sk_w — i.e. "
                            "elsewhere in the same paper, NewBasisDel's basis argument is always "
                            "something that already exists, confirming Algorithm 2's sk_rj-as-input "
                            "is a transcription error, not an intentional fixed point.",
}


def _paper_line6_literal(j: int, params: Params) -> np.ndarray:
    """Executes exactly PAPER_LINE_6, in the paper's own variable names."""
    R = H1(pk_rj, j, params)  # noqa: F821 -- pk_rj does not exist yet: THE BUG
    return R


def _paper_line7_literal(pk_rj: np.ndarray, R: np.ndarray, params: Params, rng: random.Random) -> np.ndarray:
    """Executes exactly PAPER_LINE_7, in the paper's own variable names."""
    sk_rj = new_basis_del(pk_rj, R, sk_rj, params.sigma, params.q, rng)  # noqa: F821 -- self-reference: THE BUG
    return sk_rj


def run_paper_version(j: int, pk_prev: np.ndarray, sk_prev: np.ndarray, params: Params) -> dict:
    """Attempts Algorithm 2 literally as printed. Both circular lines fail;
    we run each in isolation so the UI can show precisely which name is
    undefined and why.
    """
    trace = Trace()
    trace.note(
        "Algorithm 2 (KeyExt), as printed in the paper",
        detail="Two lines reference variables that do not exist yet at the point they are used.",
        data={"line_6": PAPER_LINE_6, "line_7": PAPER_LINE_7},
        algo="SpecDefect",
    )

    failures = []

    try:
        _paper_line6_literal(j, params)
        line6_error = None
    except Exception as e:  # noqa: BLE001 -- we want to display whatever Python raises
        line6_error = {"type": type(e).__name__, "message": str(e)}
        failures.append(("line_6", line6_error))
        trace.decision(
            "Line 6 fails: R = H1(pk_rj, j)",
            verdict=f"non-executable ({line6_error['type']})",
            evidence={"error_type": line6_error["type"], "error_message": line6_error["message"]},
            detail="pk_rj is used on the right-hand side, but Algorithm 2's only inputs are "
                   "j, pk_r{j-1}, sk_r{j-1} — pk_rj is this algorithm's OUTPUT, not an input.",
            algo="SpecDefect",
        )

    if line6_error is not None:
        # Line 7 depends on a well-formed R; supply a *correct* R (from the
        # actual previous-period key) purely so line 7's OWN circularity can
        # be demonstrated in isolation, uncontaminated by line 6's failure.
        R_for_line7 = H1(pk_prev, j, params)
        try:
            pyrng = random.Random(j)
            _paper_line7_literal(pk_prev, R_for_line7, params, pyrng)
            line7_error = None
        except Exception as e:  # noqa: BLE001
            line7_error = {"type": type(e).__name__, "message": str(e)}
            failures.append(("line_7", line7_error))
            trace.decision(
                "Line 7 fails: sk_rj = NewBasisDel(pk_rj, R, sk_rj, sigma)",
                verdict=f"non-executable ({line7_error['type']})",
                evidence={"error_type": line7_error["type"], "error_message": line7_error["message"]},
                detail="sk_rj appears as NewBasisDel's OWN INPUT on the same line that assigns "
                       "it — the interpreter must evaluate the right-hand side (which reads "
                       "sk_rj) before the assignment that would give it a value.",
                algo="SpecDefect",
            )

    trace.result(
        "Algorithm 2, executed literally as printed, is NOT EXECUTABLE",
        detail="Both circular lines fail independently; this is not a corner case, it's the algorithm as printed.",
        data={"failures": dict(failures)},
        algo="SpecDefect",
        highlight=True,
    )
    return {"success": False, "failures": dict(failures), "trace": trace.to_list()}


def run_corrected_version(J: int, params: Params, seed: int = 0) -> dict:
    """Runs the corrected single-step KeyExt (scheme.keyext) across periods
    0..J, verifying pk_rj . sk_rj = 0 (mod q) at every period."""
    trace = Trace()
    trace.correction(
        "The three-way justification for the fix",
        paper_says="Algorithm 2 line 6 uses pk_rj; line 7 uses sk_rj as NewBasisDel's own input.",
        we_do="R = H1(pk_{j-1}, j); sk_j = NewBasisDel(pk_{j-1}, R, sk_{j-1}, sigma) — "
              "everything on the right-hand side already exists.",
        because=(
            f"(1) input list: {JUSTIFICATION['input_list']} "
            f"(2) Lemma 5 signature: {JUSTIFICATION['lemma_5_signature']} "
            f"(3) Algorithm 4 analogy: {JUSTIFICATION['algorithm_4_analogy']}"
        ),
        algo="SpecDefect",
    )

    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)
    pk0, sk0 = trapgen(params, rng)
    chain = [{"period": 0, "pk": pk0, "sk": sk0, "valid": bool(np.all(mat_mod_mixed(pk0, sk0, params.q) == 0))}]

    pk, sk = pk0, sk0
    for j in range(1, J + 1):
        pk, sk = keyext(j, pk, sk, params, pyrng)
        ok = bool(np.all(mat_mod_mixed(pk, sk, params.q) == 0))
        chain.append({"period": j, "pk": pk, "sk": sk, "valid": ok})

    all_valid = all(entry["valid"] for entry in chain)
    trace.decision(
        f"Corrected KeyExt: built a valid {J}-period key chain",
        verdict="all periods valid" if all_valid else "SOME PERIOD INVALID",
        evidence={"periods_checked": J + 1, "all_valid": all_valid},
        algo="SpecDefect",
        highlight=True,
    )

    return {
        "success": all_valid,
        "chain": [
            {
                "period": e["period"],
                "valid": e["valid"],
                "pk_preview": e["pk"][:4, :12].tolist(),
                "sk_gram_schmidt_norm": gram_schmidt_norm(e["sk"]),
            }
            for e in chain
        ],
        "trace": trace.to_list(),
    }
