"""PATCH 14/15 — security boundary: BOTH attacks against an estimated bit axis.

Per (n, q): gate the honest scheme for correctness, estimate the bit-security
of its trapdoor lattice (attacks.security_estimate), then run two attacks
against the SAME frozen earlier-period database, each through its own BKZ
block-size ladder under its own budget:

  Attack 1 (PATCH 14) -- PUBLIC KEY ONLY. A kernel basis of pk_r|i, reduced.
      No secret, no theft, no TrapGen.
  Attack 2 (PATCH 06/12/15) -- STOLEN KEY. Steal sk_r|J (the current period),
      transform it backward by the PUBLIC R-product, reduce, and search the
      earlier period's frozen CT.

The verdict is RELATIVE, and that is the honest core of PATCH 15: a stolen key
only demonstrates a forward-security break when it succeeds WHERE THE PUBLIC
KEY ALONE DOES NOT. If the public key already breaks the cell, "forward
security" there is vacuous and the theft added nothing -- so `pk_broke`
supersedes `stolen_broke` in the verdict, never the other way round.

Scope, kept in the data and not only in prose:
- A cell that runs out of budget is `timed_out` => "unmeasured", never secure.
- `attack_failed` means the ladder ran to completion without a working
  trapdoor, which is still only evidence against THESE attacks at THIS budget.
- The estimate is asymptotic. At small m lattice reduction is much stronger in
  practice than the root-Hermite fit suggests, so `beta_used` (measured) and
  `beta` (estimated) are reported side by side rather than being conflated.
- A cell whose negative control PASSES is `untrusted` and is excluded from
  every count -- it is never reported as a survival.

Deviation from PATCH 15 §1 (marked, per CLAUDE.md §10): the patch asks for
q=4099. H2's twisted binomial needs q = 1 (mod 4) whenever 4 | n, and
4099 = 3 (mod 4), so that column is impossible at EVERY n in this grid
(4, 8, 16 are all divisible by 4) -- it would produce five "n/a (H2)" cells
and no measurement. q=4001 (= 1 mod 4, same ~12-bit size) is substituted and
the substitution is carried in the job config and the conclusion.
"""

from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import threading
import time
import uuid
from functools import partial
from pathlib import Path
from typing import Optional

import numpy as np

from ppseb.linalg import gram_schmidt_norm, kernel_basis_mod_q, mat_mod_mixed, strong_reduce
from ppseb.params import Params, default_params, derived_m
from ppseb.scheme import trapdoor
from ppseb.trace import jsonable

from .end_to_end import _recover_period_candidate, _test_candidate, build_frozen_history
from .nq_sweep import GATE_CHECKS, h2_valid, negative_control_unrelated_key
from .security_estimate import (estimate_bits, gaussian_heuristic, lattice_estimator_available,
                                 trapdoor_bytes)

# PATCH 15 §1 — the wide grid. 4099 -> 4001, see the module docstring.
GRID_N = (4, 8, 16)
GRID_Q = (257, 1153, 4001, 12289, 40961)
Q_SUBSTITUTIONS = {4099: 4001}
Q_SUBSTITUTION_NOTE = (
    "PATCH 15 asks for q=4099; H2's twisted binomial requires q = 1 (mod 4) when 4 | n, "
    "and 4099 = 3 (mod 4), so every n in {4, 8, 16} would be n/a there. q=4001 "
    "(= 1 mod 4, same bit-length) is substituted."
)
WIDE_GRID = tuple((n, q) for n in GRID_N for q in GRID_Q)
DEFAULT_GRID = WIDE_GRID

PAPER_DEMO_Q = 257
PAPER_DEMO_N = (4, 8)
DEFAULT_BETA_LADDER = (2, 5, 10, 20, 30, 40, 50)
DEFAULT_ATTACK_BUDGET_S = 600.0     # per attack, per cell (PATCH 15 §1: use the hours)
DEFAULT_CELL_TIMEOUT_S = 2400.0     # hard kill, 40 min
DEFAULT_MAX_HOURS = 9.0             # overall wall-clock cap, checkpoint-and-stop
DEFAULT_J = 3                       # short chain: sk_r|3 stolen, period 0 attacked
DEFAULT_RECORDS_PER_PERIOD = 8
STOLEN_TARGET_PERIOD = 0            # both attacks hit the SAME frozen period

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

OUTCOME_BROKE = "broke"
OUTCOME_FAILED = "attack_failed"
OUTCOME_TIMEOUT = "timed_out (unmeasured)"
OUTCOME_NA = "n/a (honest incorrect)"
OUTCOME_H2 = "n/a (H2)"
OUTCOME_UNTRUSTED = "untrusted"
OUTCOME_ERROR = "error"
MEASURED_OUTCOMES = (OUTCOME_BROKE, OUTCOME_FAILED)

# PATCH 15 §2 — the RELATIVE verdict.
VERDICT_UNTRUSTED = "untrusted"
VERDICT_PK = "BROKEN (public-key only)"
VERDICT_FORWARD = "forward-security break (stolen key REQUIRED)"
VERDICT_UNMEASURED = "unmeasured (timeout)"
VERDICT_FAILED = "attack failed (secure vs both, this budget)"
VERDICT_NA = "n/a (not attacked)"


def is_paper_demo(n: int, q: int) -> bool:
    """The parameters the paper's own figures use."""
    return q == PAPER_DEMO_Q and n in PAPER_DEMO_N


def repeats_for(n: int, q: int) -> int:
    """PATCH 15 §1: 2 repeats on the small, fast cells; 1 on the big ones."""
    return 2 if (n <= 8 and q <= 1153) else 1


def cell_verdict(cell: dict) -> str:
    """The relative verdict of PATCH 15 §2, as a pure function of a cell.

    Order matters and is the honest part: `pk_broke` is checked BEFORE
    `stolen_broke`, so a cell the public key already breaks can never be
    reported as a forward-security break -- there the stolen key is redundant,
    not powerful. A timeout is "unmeasured", and is never allowed to fall
    through into the "attack failed" (i.e. survived) bucket.
    """
    if cell.get("outcome") in (OUTCOME_NA, OUTCOME_H2, OUTCOME_ERROR):
        return VERDICT_NA
    if not cell.get("control_ok", True):
        return VERDICT_UNTRUSTED
    if cell.get("pk_broke"):
        return VERDICT_PK
    if cell.get("stolen_broke"):
        return VERDICT_FORWARD
    if cell.get("pk_timed_out") or cell.get("stolen_timed_out"):
        return VERDICT_UNMEASURED
    return VERDICT_FAILED


# --------------------------------------------------------------------------
# One attack = one BKZ block-size ladder under a budget
# --------------------------------------------------------------------------

def _run_ladder(label: str, make_candidate, history, target: int, params: Params, mu, u_pke,
                beta_ladder, budget_s: float) -> dict:
    """Climb `beta_ladder` until the candidate basis yields the doctor's N0 or
    the budget runs out. `make_candidate(beta) -> (basis, membership_ok,
    method, reduced_norm)` is the only thing that differs between the two
    attacks -- everything downstream (Level 1 gate, Trapdoor, Verify against
    the frozen CT) is the SAME `_test_candidate` path, so the two are
    comparable by construction.
    """
    attempts: list[dict] = []
    broke_at = None
    started = time.time()
    exhausted = False
    for beta in beta_ladder:
        if time.time() - started > budget_s:
            exhausted = True
            break
        t_beta = time.time()
        try:
            basis, membership, method, reduced_norm = make_candidate(beta)
        except Exception as e:  # noqa: BLE001 -- a reduction can blow up at large m
            attempts.append({"beta": beta, "error": f"{type(e).__name__}: {e}",
                             "runtime_s": time.time() - t_beta})
            continue
        res = _test_candidate(history, target, basis, params, mu, u_pke, source_label=label,
                              membership_ok=membership,
                              reduced_norm=reduced_norm if reduced_norm is not None
                              else gram_schmidt_norm(basis),
                              reducer_method=method, rng_tag=f"{label}{beta}")
        attempts.append({"beta": beta, "gs_norm": res["gs_norm"], "break": res["level2_search_break"],
                         "N0_star": res["N0_star"], "N0_legit": res["N0_legit"],
                         "level1_norm_ok": res["level1_norm_ok"], "membership_ok": res["membership_ok"],
                         "level3": res["level3_plaintext_break"],
                         "runtime_s": time.time() - t_beta, "method": method})
        if res["level2_search_break"]:
            broke_at = beta
            break
    runtime = time.time() - started
    timed_out = broke_at is None and (exhausted or runtime > budget_s)
    outcome = OUTCOME_BROKE if broke_at is not None else (OUTCOME_TIMEOUT if timed_out else OUTCOME_FAILED)
    return {"attempts": attempts, "beta": broke_at, "broke": broke_at is not None,
            "timed_out": timed_out, "runtime_s": runtime, "outcome": outcome,
            "level3": any(a.get("level3") for a in attempts)}


def _pk_candidate(beta: int, pk_i: np.ndarray, q: int):
    """Attack 1's move: a basis of L_perp_q(pk_i) built from the PUBLIC key
    alone (kernel_basis_mod_q includes the q*e_j vectors), then BKZ-reduced."""
    basis, method = strong_reduce(kernel_basis_mod_q(pk_i, q), block_size=beta)
    membership = bool(np.all(mat_mod_mixed(pk_i, basis, q) == 0))
    return basis, membership, method, gram_schmidt_norm(basis)


def _stolen_candidate(beta: int, history, target: int, J: int, stolen_sk: np.ndarray, params: Params):
    """Attack 2's move: R_prod^-1 . sk_r|J, then BKZ-reduced. The ONLY secret
    read is `stolen_sk`; every R and pk comes from `history`, whose PeriodDB
    carries no secret key at all (see test_stolen_reads_only_stolen_sk)."""
    basis, membership, _trivial, reduced_norm, method = _recover_period_candidate(
        history, target, J, stolen_sk, params, reducer=partial(strong_reduce, block_size=beta),
    )
    return basis, membership, method, reduced_norm


# --------------------------------------------------------------------------
# One cell
# --------------------------------------------------------------------------

def run_boundary_cell(n: int, q: int, J: int = DEFAULT_J,
                      records_per_period: int = DEFAULT_RECORDS_PER_PERIOD, seed: int = 1400,
                      beta_ladder=DEFAULT_BETA_LADDER,
                      attack_budget_s: float = DEFAULT_ATTACK_BUDGET_S,
                      run_stolen: bool = True) -> dict:
    started = time.time()
    m = derived_m(n, q)
    target = STOLEN_TARGET_PERIOD
    cell = {"n": n, "q": q, "m": m, "J": J, "seed": seed, "target_period": target,
            "periods_back": J - target,
            "paper_demo": is_paper_demo(n, q),
            "trapdoor_bytes": trapdoor_bytes(m, q),
            "beta_ladder": list(beta_ladder), "attack_budget_s": attack_budget_s,
            "estimator_backend_available": lattice_estimator_available()}

    reason = h2_valid(n, q)
    if reason:
        cell.update(outcome=OUTCOME_H2, h2_error=reason, runtime_s=time.time() - started)
        cell["verdict"] = cell_verdict(cell)
        return cell

    base = default_params()
    p = Params(n=n, q=q, sigma=base.sigma, l=base.l, usability_C=base.usability_C, m=0)
    history, _stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(
        J, p, seed=seed, records_per_period=records_per_period,
        honest_checks=True, max_seed_retries=0)
    cell["sigma"] = p.sigma

    checks = [e.legit_trap_demo["checks"] for e in history]
    failed = sorted({c for ch in checks for c in GATE_CHECKS if not ch[c]})
    cell["gate_failed_checks"] = failed
    cell["honest_checks"] = checks[target]

    target_norm = checks[target]["period_gs"]
    cell["target_norm"] = target_norm
    cell["estimate"] = estimate_bits(n, q, m, target_norm, sigma=p.sigma)
    cell["estimate"]["target_provenance"] = "measured honest basis"
    cell["bits"] = cell["estimate"]["bits"]

    # Cost of one Trapdoor call at these parameters (PATCH 14 §4's timing proxy).
    equivalent_basis = _honest_like_basis(history, p)
    t0 = time.time()
    trapdoor(history[target].pk_ri, equivalent_basis, "flu", target, mu, p, random.Random(seed))
    cell["honest_trapdoor_s"] = time.time() - t0

    if failed:
        cell.update(outcome=OUTCOME_NA, runtime_s=time.time() - started)
        cell["verdict"] = cell_verdict(cell)
        return cell

    control = negative_control_unrelated_key(history, target, p, mu, seed)
    cell["control"] = control
    cell["control_ok"] = not control["passed"]
    if control["passed"]:
        cell.update(outcome=OUTCOME_UNTRUSTED, runtime_s=time.time() - started)
        cell["verdict"] = cell_verdict(cell)
        return cell

    # Attack 1 — public key only.
    pk_i = history[target].pk_ri
    pk = _run_ladder("public_key_only", lambda b: _pk_candidate(b, pk_i, q),
                     history, target, p, mu, u_pke, beta_ladder, attack_budget_s)
    cell.update(pk_broke=pk["broke"], pk_beta=pk["beta"], pk_runtime_s=pk["runtime_s"],
                pk_timed_out=pk["timed_out"], pk_outcome=pk["outcome"], pk_attempts=pk["attempts"],
                pk_level3=pk["level3"])

    # Attack 2 — stolen sk_r|J, transformed backward by the public R-product.
    if run_stolen:
        st = _run_ladder("stolen_key", lambda b: _stolen_candidate(b, history, target, J, stolen_sk, p),
                         history, target, p, mu, u_pke, beta_ladder, attack_budget_s)
        cell.update(stolen_broke=st["broke"], stolen_beta=st["beta"], stolen_runtime_s=st["runtime_s"],
                    stolen_timed_out=st["timed_out"], stolen_outcome=st["outcome"],
                    stolen_attempts=st["attempts"], stolen_level3=st["level3"])
    else:
        cell.update(stolen_broke=False, stolen_beta=None, stolen_runtime_s=0.0,
                    stolen_timed_out=True, stolen_outcome=OUTCOME_TIMEOUT,
                    stolen_attempts=[], stolen_level3=False,
                    stolen_skipped="not run in this job")

    # Back-compatible top-level fields: the PATCH 14 plot and conclusion read
    # the PUBLIC-KEY attack, which is still the headline axis.
    cell["attempts"] = pk["attempts"]
    cell["beta_used"] = pk["beta"] if pk["beta"] is not None else (
        pk["attempts"][-1]["beta"] if pk["attempts"] else None)
    cell["broke"] = pk["broke"]
    cell["attack_runtime_s"] = pk["runtime_s"]
    cell["outcome"] = pk["outcome"]
    cell["stolen_helps"] = bool(cell["stolen_broke"] and not cell["pk_broke"])
    cell["verdict"] = cell_verdict(cell)
    cell["runtime_s"] = time.time() - started
    return cell


def _honest_like_basis(history, params: Params) -> np.ndarray:
    """A basis of the same lattice for the honest-timing proxy. PeriodDB carries
    no secret key, so this times Trapdoor on an equivalent basis, not on the
    doctor's own -- it measures the cost of the operation at these parameters."""
    basis, _method = strong_reduce(kernel_basis_mod_q(history[STOLEN_TARGET_PERIOD].pk_ri, params.q))
    return basis


def run_cell_with_timeout(n, q, J, records_per_period, seed, beta_ladder, attack_budget_s,
                          timeout_s, run_stolen: bool = True) -> dict:
    """One cell per subprocess -- see attacks/nq_cell_worker.py for why this is a
    plain subprocess and not multiprocessing."""
    from . import boundary_cell_worker

    payload = json.dumps({"n": n, "q": q, "J": J, "records_per_period": records_per_period,
                          "seed": seed, "beta_ladder": list(beta_ladder),
                          "attack_budget_s": attack_budget_s, "run_stolen": run_stolen})
    started = time.time()
    m = derived_m(n, q)
    base = {"n": n, "q": q, "m": m, "J": J, "seed": seed, "paper_demo": is_paper_demo(n, q),
            "trapdoor_bytes": trapdoor_bytes(m, q)}
    # A cell that dies on the timeout returns nothing, so estimate it HERE too --
    # otherwise the unmeasured cells carry no bits and cannot be plotted at all,
    # which is exactly the half of the picture they exist to populate. The honest
    # basis was never measured, so the target norm is the Gaussian heuristic (the
    # lattice's expected shortest vector), and the record says so.
    fallback_target = gaussian_heuristic(n, q, m)
    fallback = estimate_bits(n, q, m, fallback_target, sigma=default_params().sigma)
    fallback["target_provenance"] = "gaussian_heuristic (honest basis not measured)"
    base["estimate"] = fallback
    base["bits"] = fallback["bits"]
    base["target_norm"] = fallback_target
    try:
        proc = subprocess.run([sys.executable, "-m", "attacks.boundary_cell_worker", payload],
                              capture_output=True, text=True, timeout=timeout_s,
                              cwd=str(Path(__file__).resolve().parent.parent))
    except subprocess.TimeoutExpired:
        out = {**base, "outcome": OUTCOME_TIMEOUT, "timed_out": True,
               "pk_broke": False, "pk_timed_out": True, "pk_outcome": OUTCOME_TIMEOUT,
               "stolen_broke": False, "stolen_timed_out": True, "stolen_outcome": OUTCOME_TIMEOUT,
               # The control never ran here, so nothing is claimed about it; the
               # cell is "unmeasured", which is neither trusted nor a survival.
               "control_ran": False, "stolen_helps": False,
               "timeout_note": "killed at the cell timeout; it may not have reached the attack ladder",
               "runtime_s": time.time() - started}
        out["verdict"] = cell_verdict(out)
        return out
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith(boundary_cell_worker.MARKER)), None)
    if line is None:
        detail = (proc.stderr or proc.stdout or "worker produced no output").strip()
        out = {**base, "outcome": OUTCOME_ERROR, "error": detail[-2000:],
               "runtime_s": time.time() - started}
        out["verdict"] = cell_verdict(out)
        return out
    return json.loads(line[len(boundary_cell_worker.MARKER):])


def merge_repeats(results: list[dict]) -> dict:
    """Fold a cell's repeats into one record (PATCH 15 §1).

    An attack that succeeded in ANY repeat broke the cell -- a break is an
    existence claim, and one success is a success. A cell is trusted only if
    the control failed in EVERY repeat. "Timed out" survives only when nothing
    broke, so a repeat that ran out of budget can never downgrade a measured
    break, nor be upgraded into a survival.
    """
    if len(results) == 1:
        out = dict(results[0])
        out["repeats"] = 1
        out["repeat_seeds"] = [results[0].get("seed")]
        return out
    # Describe the merged cell with a repeat that actually reached the attacks:
    # a repeat whose honest gate failed carries no ladder, no control and no
    # norms, so using it as the base would attach a break to a record that
    # never ran one. The break flags below still come from ALL repeats.
    base = next((r for r in results if r.get("pk_attempts")), results[0])
    first = dict(base)
    first["na_repeats"] = [{"seed": r.get("seed"), "outcome": r.get("outcome"),
                            "gate_failed_checks": r.get("gate_failed_checks")}
                           for r in results if not r.get("pk_attempts")]
    broke_pk = any(r.get("pk_broke") for r in results)
    broke_st = any(r.get("stolen_broke") for r in results)
    first["pk_broke"] = broke_pk
    first["stolen_broke"] = broke_st
    first["pk_beta"] = min((r["pk_beta"] for r in results if r.get("pk_beta") is not None), default=None)
    first["stolen_beta"] = min((r["stolen_beta"] for r in results if r.get("stolen_beta") is not None), default=None)
    first["pk_timed_out"] = (not broke_pk) and any(r.get("pk_timed_out") for r in results)
    first["stolen_timed_out"] = (not broke_st) and any(r.get("stolen_timed_out") for r in results)
    first["control_ok"] = all(r.get("control_ok", True) for r in results)
    first["broke"] = broke_pk
    first["beta_used"] = first["pk_beta"] if first["pk_beta"] is not None else first.get("beta_used")
    first["outcome"] = (OUTCOME_BROKE if broke_pk else
                        OUTCOME_TIMEOUT if first["pk_timed_out"] else
                        first.get("outcome", OUTCOME_FAILED))
    first["stolen_helps"] = bool(broke_st and not broke_pk)
    first["verdict"] = cell_verdict(first)
    first["repeats"] = len(results)
    first["repeats_attacked"] = sum(1 for r in results if r.get("pk_attempts"))
    first["repeat_seeds"] = [r.get("seed") for r in results]
    first["repeat_outcomes"] = [{"seed": r.get("seed"), "pk": r.get("pk_outcome", r.get("outcome")),
                                 "stolen": r.get("stolen_outcome")} for r in results]
    first["runtime_s"] = sum(r.get("runtime_s") or 0.0 for r in results)
    return first


# --------------------------------------------------------------------------
# Conclusion
# --------------------------------------------------------------------------

def stolen_key_tally(cells: list[dict]) -> dict:
    """PATCH 15 §3's Plot-2 caption, computed from the data.

    Only cells where BOTH attacks actually ran and the control held are
    counted; an untrusted, n/a or timed-out cell says nothing about whether
    the stolen key helps, so it is listed separately rather than folded into
    "neither broke".
    """
    counted = [c for c in cells
               if c.get("control_ok", True)
               and c.get("outcome") not in (OUTCOME_NA, OUTCOME_H2, OUTCOME_ERROR, OUTCOME_UNTRUSTED)]
    helps = [c for c in counted if c.get("stolen_broke") and not c.get("pk_broke")]
    both = [c for c in counted if c.get("stolen_broke") and c.get("pk_broke")]
    pk_only = [c for c in counted if c.get("pk_broke") and not c.get("stolen_broke")]
    neither_measured = [c for c in counted
                        if not c.get("pk_broke") and not c.get("stolen_broke")
                        and not (c.get("pk_timed_out") or c.get("stolen_timed_out"))]
    unmeasured = [c for c in cells if c.get("verdict") == VERDICT_UNMEASURED]
    counted_ids = {id(c) for c in counted}
    excluded = [c for c in cells if id(c) not in counted_ids]
    return {"considered": len(counted), "stolen_helps": helps, "both_broke": both,
            "pk_only": pk_only, "neither": neither_measured, "unmeasured": unmeasured,
            "excluded": excluded}


def build_conclusion(cells: list[dict]) -> str:
    measured = [c for c in cells if c.get("outcome") in MEASURED_OUTCOMES and c.get("bits") is not None]
    broke = [c for c in cells if c.get("outcome") == OUTCOME_BROKE]
    timed = [c for c in cells if c.get("outcome") == OUTCOME_TIMEOUT]
    failed = [c for c in cells if c.get("outcome") == OUTCOME_FAILED]
    na = [c for c in cells if c.get("outcome") in (OUTCOME_NA, OUTCOME_H2)]
    untrusted = [c for c in cells if c.get("outcome") == OUTCOME_UNTRUSTED]
    backend = next((c["estimate"]["backend"] for c in cells if c.get("estimate")), "lindner-peikert-fit")

    def label(c):
        bits = c.get("bits")
        return f"(n={c['n']}, q={c['q']}{'' if bits is None else f', ~{bits:.0f} bits'})"

    parts = []
    if broke:
        broke_bits = [c["bits"] for c in broke if c.get("bits") is not None]
        top = f"~{max(broke_bits):.0f} bits" if broke_bits else "an unestimated level"
        parts.append(
            f"The public-key-only attack (no secret key) recovers a working trapdoor at "
            f"{', '.join(label(c) for c in broke)} — up to {top}.")
        papers = [c for c in broke if c.get("paper_demo")]
        if papers:
            parts.append(
                f"That includes the paper's own demonstration parameters "
                f"{', '.join(label(c) for c in papers)}, so its forward-security and "
                f"confidentiality claims are vacuous at the parameters it evaluates: the public "
                f"key alone yields search.")

    # PATCH 15 §2/§3 — the relative result, stated whether or not it is positive.
    tally = stolen_key_tally(cells)
    if tally["considered"]:
        if tally["stolen_helps"]:
            parts.append(
                f"The stolen key provides a break BEYOND the public key in "
                f"{len(tally['stolen_helps'])} of {tally['considered']} cells where both attacks ran: "
                f"{', '.join(label(c) for c in tally['stolen_helps'])} — there the public key alone "
                f"failed and the stolen sk_r|J succeeded, which is a genuine forward-security break.")
        else:
            parts.append(
                f"In none of the {tally['considered']} cells where both attacks ran did the stolen key "
                f"succeed where the public key alone failed: in {len(tally['both_broke'])} cell(s) both "
                f"broke (the theft was redundant) and in {len(tally['neither'])} cell(s) neither broke "
                f"within budget. So at every tested parameter, 'forward security' is either vacuous — "
                f"the public key already breaks the earlier period — or the stolen key is no stronger "
                f"than public knowledge.")
    if failed:
        ceilings = {max(c["beta_ladder"]) for c in failed if c.get("beta_ladder")}
        ceiling = f" up to BKZ block size {max(ceilings)}" if ceilings else ""
        parts.append(f"The public-key attack ran its whole ladder{ceiling} without a working trapdoor at "
                     f"{', '.join(label(c) for c in failed)} — evidence against THIS attack at THIS "
                     f"ladder ceiling, not a security proof.")
    if timed:
        parts.append(
            f"At {', '.join(label(c) for c in timed)} the attack exhausted its budget: UNMEASURED, "
            f"not proven secure. There key security reduces to the standard LWE/SIS hardness the "
            f"estimate quantifies (backend: {backend}).")
    if na:
        parts.append(f"No attack point at {', '.join(label(c) for c in na)} (honest scheme incorrect or H2 invalid).")
    if untrusted:
        parts.append(f"{', '.join(label(c) for c in untrusted)} untrusted (negative control passed); excluded from every count.")
    if measured:
        parts.append(
            "The bit axis is an estimate; the break/no-break outcome is measured. They are "
            "reported separately and never merged.")
    parts.append(Q_SUBSTITUTION_NOTE)
    parts.append(
        "Demo-scale n and q throughout; the estimate is asymptotic and is unreliable at these "
        "small dimensions, where reduction performs better in practice than the fit predicts.")
    return " ".join(parts)


# --------------------------------------------------------------------------
# Job: JSONL checkpoint + resume + wall-clock cap (PATCH 08 idiom)
# --------------------------------------------------------------------------

def cell_key(n: int, q: int, seed: int, repeat: int) -> str:
    """Idempotency key: resuming never re-runs, and never double-counts, a
    (cell, repeat) that already landed in the JSONL."""
    return f"n{n}|q{q}|s{seed}|r{repeat}"


def _paths(job_id: str) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return (RESULTS_DIR / f"secbound_{job_id}.jsonl", RESULTS_DIR / f"secbound_{job_id}.meta.json")


def append_record(job_id: str, record: dict) -> None:
    jsonl_path, _meta = _paths(job_id)
    with jsonl_path.open("a") as fh:
        fh.write(json.dumps(jsonable(record)) + "\n")
        fh.flush()
        os.fsync(fh.fileno())


def load_records(job_id: str) -> list[dict]:
    """Every completed (cell, repeat). Tolerates a torn final line from a
    crash mid-append, and de-duplicates by key (first write wins)."""
    jsonl_path, _meta = _paths(job_id)
    if not jsonl_path.exists():
        return []
    out, seen = [], set()
    for line in jsonl_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = rec.get("key")
        if key in seen:
            continue
        seen.add(key)
        out.append(rec)
    return out


def write_meta(job_id: str, meta: dict) -> None:
    _jsonl, meta_path = _paths(job_id)
    tmp = meta_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(jsonable(meta), indent=2))
    tmp.replace(meta_path)


def load_meta(job_id: str) -> Optional[dict]:
    _jsonl, meta_path = _paths(job_id)
    if not meta_path.exists():
        return None
    try:
        return json.loads(meta_path.read_text())
    except json.JSONDecodeError:
        return None


def _merged_cells(records: list[dict]) -> list[dict]:
    by_cell: dict[tuple[int, int], list[dict]] = {}
    for rec in records:
        by_cell.setdefault((rec["cell"]["n"], rec["cell"]["q"]), []).append(rec["cell"])
    return [merge_repeats(v) for v in by_cell.values()]


class BoundaryJob:
    def __init__(self, job_id, grid, J, records_per_period, seed, beta_ladder, attack_budget_s,
                 timeout_s, max_hours=DEFAULT_MAX_HOURS, run_stolen=True):
        self.job_id = job_id
        self.config = {"grid": [list(c) for c in grid], "J": J, "records_per_period": records_per_period,
                       "seed": seed, "beta_ladder": list(beta_ladder),
                       "attack_budget_s": attack_budget_s, "cell_timeout_s": timeout_s,
                       "max_hours": max_hours, "run_stolen": run_stolen,
                       "target_period": STOLEN_TARGET_PERIOD,
                       "q_substitutions": {str(k): v for k, v in Q_SUBSTITUTIONS.items()},
                       "q_substitution_note": Q_SUBSTITUTION_NOTE}
        self.status = "running"
        self.started_at = time.time()
        self.stopped_early: Optional[str] = None
        self.thread: Optional[threading.Thread] = None
        self.records: list[dict] = load_records(job_id)   # resume: already-done units

    @property
    def cells(self) -> list[dict]:
        return _merged_cells(self.records)

    def _units(self):
        for (n, q) in self.config["grid"]:
            for repeat in range(repeats_for(n, q)):
                seed = self.config["seed"] + 1000 * repeat
                yield (n, q, repeat, seed, cell_key(n, q, seed, repeat))

    def snapshot(self) -> dict:
        cells = self.cells
        units = list(self._units())
        done_keys = {r["key"] for r in self.records}
        return {"job_id": self.job_id, "status": self.status, "config": self.config,
                "done": len(cells), "total": len({(n, q) for (n, q, *_r) in units}),
                "units_done": len(done_keys), "units_total": len(units),
                "stopped_early": self.stopped_early,
                "elapsed_s": time.time() - self.started_at, "cells": cells,
                "stolen_key_tally": {k: (v if isinstance(v, int) else
                                         [{"n": c["n"], "q": c["q"], "bits": c.get("bits")} for c in v])
                                     for k, v in stolen_key_tally(cells).items()} if cells else None,
                "conclusion": build_conclusion(cells) if cells else None}

    def save(self) -> None:
        write_meta(self.job_id, {k: v for k, v in self.snapshot().items() if k != "cells"})

    def run(self) -> None:
        try:
            cfg = self.config
            deadline = self.started_at + cfg["max_hours"] * 3600
            done_keys = {r["key"] for r in self.records}
            for (n, q, repeat, seed, key) in self._units():
                if key in done_keys:
                    continue
                if time.time() > deadline:
                    self.stopped_early = (
                        f"wall-clock cap of {cfg['max_hours']}h reached; remaining cells were NOT run "
                        f"and are not reported as secure")
                    self.status = "stopped (wall-clock cap)"
                    self.save()
                    return
                cell = run_cell_with_timeout(
                    n, q, cfg["J"], cfg["records_per_period"], seed,
                    cfg["beta_ladder"], cfg["attack_budget_s"], cfg["cell_timeout_s"],
                    run_stolen=cfg["run_stolen"])
                cell.setdefault("seed", seed)
                record = {"key": key, "n": n, "q": q, "repeat": repeat, "seed": seed,
                          "finished_at": time.time(), "cell": cell}
                append_record(self.job_id, record)
                self.records.append(record)
                self.save()
            self.status = "done"
        except Exception as e:  # noqa: BLE001
            self.status = f"failed: {type(e).__name__}: {e}"
        self.save()


_JOBS: dict[str, BoundaryJob] = {}


def start_job(grid=DEFAULT_GRID, J=DEFAULT_J, records_per_period=DEFAULT_RECORDS_PER_PERIOD,
              seed=1400, beta_ladder=DEFAULT_BETA_LADDER, attack_budget_s=DEFAULT_ATTACK_BUDGET_S,
              timeout_s=DEFAULT_CELL_TIMEOUT_S, max_hours=DEFAULT_MAX_HOURS, run_stolen=True,
              job_id: Optional[str] = None) -> str:
    """Start a new job, or resume `job_id` (its completed units are skipped)."""
    job = BoundaryJob(job_id or uuid.uuid4().hex[:12], grid, J, records_per_period, seed,
                      beta_ladder, attack_budget_s, timeout_s, max_hours, run_stolen)
    _JOBS[job.job_id] = job
    job.save()
    job.thread = threading.Thread(target=job.run, name=f"boundary-{job.job_id}", daemon=True)
    job.thread.start()
    return job.job_id


def job_snapshot(job_id: str) -> Optional[dict]:
    job = _JOBS.get(job_id)
    if job is not None:
        return jsonable(job.snapshot())
    meta = load_meta(job_id)
    if meta is None:
        # A PATCH 14 job, written before the JSONL format: still readable, so a
        # run measured earlier does not silently disappear from the UI.
        legacy = RESULTS_DIR / f"boundary_{job_id}.json"
        return json.loads(legacy.read_text()) if legacy.exists() else None
    cells = _merged_cells(load_records(job_id))
    return jsonable({**meta, "cells": cells,
                     "conclusion": build_conclusion(cells) if cells else meta.get("conclusion")})


def list_jobs() -> list[dict]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    paths = (sorted(RESULTS_DIR.glob("secbound_*.meta.json"), reverse=True)
             + sorted(RESULTS_DIR.glob("boundary_*.json"), reverse=True))  # PATCH 14 runs
    for path in paths:
        try:
            d = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        out.append({k: d.get(k) for k in ("job_id", "status", "done", "total", "config",
                                          "units_done", "units_total", "stopped_early")})
    return out
