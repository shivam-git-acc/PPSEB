"""PATCH 14 — security boundary: the public-key-only attack against an
estimated bit-security axis.

Per (n, q): gate the honest scheme for correctness, estimate the bit-security
of its trapdoor lattice (attacks.security_estimate), then run the public-key-
only attack -- no secret, no TrapGen -- through a BKZ block-size ladder under a
hard budget, recording the block size at which it broke.

Scope, kept in the data and not only in prose:
- A cell that runs out of budget is `timed_out` => "unmeasured", never secure.
- `attack_failed` means the ladder ran to completion without a working
  trapdoor, which is still only evidence against THIS attack.
- The estimate is asymptotic. At m=72 lattice reduction is much stronger in
  practice than the root-Hermite fit suggests, so `beta_used` (measured) and
  `beta` (estimated) are reported side by side rather than being conflated.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Optional

import numpy as np

from ppseb.linalg import gram_schmidt_norm, kernel_basis_mod_q, mat_mod_mixed, strong_reduce
from ppseb.params import Params, default_params, derived_m
from ppseb.scheme import trapdoor
from ppseb.trace import jsonable

from .end_to_end import build_frozen_history, _test_candidate
from .nq_sweep import GATE_CHECKS, h2_valid, negative_control_unrelated_key
from .security_estimate import estimate_bits, lattice_estimator_available, trapdoor_bytes

DEFAULT_GRID = ((4, 257), (8, 257), (4, 1153), (8, 1153), (4, 4001), (8, 4001),
                (16, 12289), (8, 40961))
PAPER_DEMO_Q = 257
PAPER_DEMO_N = (4, 8)
DEFAULT_BETA_LADDER = (2, 5, 10, 20, 30, 40, 50)
DEFAULT_ATTACK_BUDGET_S = 120.0
DEFAULT_CELL_TIMEOUT_S = 1800.0
DEFAULT_J = 2
DEFAULT_RECORDS_PER_PERIOD = 8

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

OUTCOME_BROKE = "broke"
OUTCOME_FAILED = "attack_failed"
OUTCOME_TIMEOUT = "timed_out (unmeasured)"
OUTCOME_NA = "n/a (honest incorrect)"
OUTCOME_H2 = "n/a (H2)"
OUTCOME_UNTRUSTED = "untrusted"
OUTCOME_ERROR = "error"
MEASURED_OUTCOMES = (OUTCOME_BROKE, OUTCOME_FAILED)


def is_paper_demo(n: int, q: int) -> bool:
    """The parameters the paper's own figures use."""
    return q == PAPER_DEMO_Q and n in PAPER_DEMO_N


def run_boundary_cell(n: int, q: int, J: int = DEFAULT_J,
                      records_per_period: int = DEFAULT_RECORDS_PER_PERIOD, seed: int = 1400,
                      beta_ladder=DEFAULT_BETA_LADDER,
                      attack_budget_s: float = DEFAULT_ATTACK_BUDGET_S) -> dict:
    started = time.time()
    m = derived_m(n, q)
    cell = {"n": n, "q": q, "m": m, "J": J, "seed": seed,
            "paper_demo": is_paper_demo(n, q),
            "trapdoor_bytes": trapdoor_bytes(m, q),
            "beta_ladder": list(beta_ladder), "attack_budget_s": attack_budget_s,
            "estimator_backend_available": lattice_estimator_available()}

    reason = h2_valid(n, q)
    if reason:
        cell.update(outcome=OUTCOME_H2, h2_error=reason, runtime_s=time.time() - started)
        return cell

    base = default_params()
    p = Params(n=n, q=q, sigma=base.sigma, l=base.l, usability_C=base.usability_C, m=0)
    history, _stolen_pk, _stolen_sk, mu, u_pke = build_frozen_history(
        J, p, seed=seed, records_per_period=records_per_period,
        honest_checks=True, max_seed_retries=0)
    cell["sigma"] = p.sigma

    checks = [e.legit_trap_demo["checks"] for e in history]
    failed = sorted({c for ch in checks for c in GATE_CHECKS if not ch[c]})
    cell["gate_failed_checks"] = failed
    cell["honest_checks"] = checks[0]

    target_norm = checks[0]["period_gs"]
    cell["target_norm"] = target_norm
    cell["estimate"] = estimate_bits(n, q, m, target_norm, sigma=p.sigma)
    cell["bits"] = cell["estimate"]["bits"]

    # Cost of one Trapdoor call at these parameters (PATCH 14 §4's timing proxy).
    equivalent_basis = _honest_like_basis(history, p)
    t0 = time.time()
    trapdoor(history[0].pk_ri, equivalent_basis, "flu", 0, mu, p, random.Random(seed))
    cell["honest_trapdoor_s"] = time.time() - t0

    if failed:
        cell.update(outcome=OUTCOME_NA, runtime_s=time.time() - started)
        return cell

    control = negative_control_unrelated_key(history, 0, p, mu, seed)
    cell["control"] = control
    if control["passed"]:
        cell.update(outcome=OUTCOME_UNTRUSTED, runtime_s=time.time() - started)
        return cell

    # The public-key-only attack, through a BKZ block-size ladder under a budget.
    attempts = []
    broke_at = None
    attack_started = time.time()
    exhausted = False
    for beta in beta_ladder:
        if time.time() - attack_started > attack_budget_s:
            exhausted = True
            break
        t_beta = time.time()
        basis, method = strong_reduce(kernel_basis_mod_q(history[0].pk_ri, q), block_size=beta)
        membership = bool(np.all(mat_mod_mixed(history[0].pk_ri, basis, q) == 0))
        res = _test_candidate(history, 0, basis, p, mu, u_pke, source_label="public_key_only",
                              membership_ok=membership, reduced_norm=gram_schmidt_norm(basis),
                              reducer_method=method, rng_tag=f"boundary{beta}")
        attempts.append({"beta": beta, "gs_norm": res["gs_norm"], "break": res["level2_search_break"],
                         "N0_star": res["N0_star"], "N0_legit": res["N0_legit"],
                         "runtime_s": time.time() - t_beta, "method": method})
        if res["level2_search_break"]:
            broke_at = beta
            break
    else:
        exhausted = False

    cell["attempts"] = attempts
    cell["beta_used"] = broke_at if broke_at is not None else (attempts[-1]["beta"] if attempts else None)
    cell["broke"] = broke_at is not None
    cell["attack_runtime_s"] = time.time() - attack_started
    if broke_at is not None:
        cell["outcome"] = OUTCOME_BROKE
    elif exhausted or cell["attack_runtime_s"] > attack_budget_s:
        cell["outcome"] = OUTCOME_TIMEOUT
    else:
        cell["outcome"] = OUTCOME_FAILED
    cell["runtime_s"] = time.time() - started
    return cell


def _honest_like_basis(history, params: Params) -> np.ndarray:
    """A basis of the same lattice for the honest-timing proxy. PeriodDB carries
    no secret key, so this times Trapdoor on an equivalent basis, not on the
    doctor's own -- it measures the cost of the operation at these parameters."""
    basis, _method = strong_reduce(kernel_basis_mod_q(history[0].pk_ri, params.q))
    return basis


def run_cell_with_timeout(n, q, J, records_per_period, seed, beta_ladder, attack_budget_s,
                          timeout_s) -> dict:
    """One cell per subprocess -- see attacks/nq_cell_worker.py for why this is a
    plain subprocess and not multiprocessing."""
    from . import boundary_cell_worker

    payload = json.dumps({"n": n, "q": q, "J": J, "records_per_period": records_per_period,
                          "seed": seed, "beta_ladder": list(beta_ladder),
                          "attack_budget_s": attack_budget_s})
    started = time.time()
    m = derived_m(n, q)
    base = {"n": n, "q": q, "m": m, "paper_demo": is_paper_demo(n, q),
            "trapdoor_bytes": trapdoor_bytes(m, q)}
    try:
        proc = subprocess.run([sys.executable, "-m", "attacks.boundary_cell_worker", payload],
                              capture_output=True, text=True, timeout=timeout_s,
                              cwd=str(Path(__file__).resolve().parent.parent))
    except subprocess.TimeoutExpired:
        return {**base, "outcome": OUTCOME_TIMEOUT, "timed_out": True, "runtime_s": time.time() - started}
    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith(boundary_cell_worker.MARKER)), None)
    if line is None:
        detail = (proc.stderr or proc.stdout or "worker produced no output").strip()
        return {**base, "outcome": OUTCOME_ERROR, "error": detail[-2000:], "runtime_s": time.time() - started}
    return json.loads(line[len(boundary_cell_worker.MARKER):])


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
    if failed:
        parts.append(f"The attack ran to completion without a working trapdoor at "
                     f"{', '.join(label(c) for c in failed)}.")
    if timed:
        parts.append(
            f"At {', '.join(label(c) for c in timed)} the attack exhausted its budget: UNMEASURED, "
            f"not proven secure. There key security reduces to the standard LWE/SIS hardness the "
            f"estimate quantifies (backend: {backend}).")
    if na:
        parts.append(f"No attack point at {', '.join(label(c) for c in na)} (honest scheme incorrect or H2 invalid).")
    if untrusted:
        parts.append(f"{', '.join(label(c) for c in untrusted)} untrusted (negative control passed).")
    if measured:
        parts.append(
            "The bit axis is an estimate; the break/no-break outcome is measured. They are "
            "reported separately and never merged.")
    parts.append(
        "Demo-scale n and q throughout; the estimate is asymptotic and is unreliable at these "
        "small dimensions, where reduction performs better in practice than the fit predicts.")
    return " ".join(parts)


class BoundaryJob:
    def __init__(self, job_id, grid, J, records_per_period, seed, beta_ladder, attack_budget_s, timeout_s):
        self.job_id = job_id
        self.config = {"grid": [list(c) for c in grid], "J": J, "records_per_period": records_per_period,
                       "seed": seed, "beta_ladder": list(beta_ladder),
                       "attack_budget_s": attack_budget_s, "cell_timeout_s": timeout_s}
        self.cells: list[dict] = []
        self.status = "running"
        self.started_at = time.time()
        self.thread: Optional[threading.Thread] = None

    def path(self) -> Path:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        return RESULTS_DIR / f"boundary_{self.job_id}.json"

    def snapshot(self) -> dict:
        return {"job_id": self.job_id, "status": self.status, "config": self.config,
                "done": len(self.cells), "total": len(self.config["grid"]),
                "elapsed_s": time.time() - self.started_at, "cells": self.cells,
                "conclusion": build_conclusion(self.cells) if self.cells else None}

    def save(self) -> None:
        tmp = self.path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(jsonable(self.snapshot()), indent=2))
        tmp.replace(self.path())

    def run(self) -> None:
        try:
            cfg = self.config
            for (n, q) in cfg["grid"]:
                self.cells.append(run_cell_with_timeout(
                    n, q, cfg["J"], cfg["records_per_period"], cfg["seed"],
                    cfg["beta_ladder"], cfg["attack_budget_s"], cfg["cell_timeout_s"]))
                self.save()
            self.status = "done"
        except Exception as e:  # noqa: BLE001
            self.status = f"failed: {type(e).__name__}: {e}"
        self.save()


_JOBS: dict[str, BoundaryJob] = {}


def start_job(grid=DEFAULT_GRID, J=DEFAULT_J, records_per_period=DEFAULT_RECORDS_PER_PERIOD,
              seed=1400, beta_ladder=DEFAULT_BETA_LADDER, attack_budget_s=DEFAULT_ATTACK_BUDGET_S,
              timeout_s=DEFAULT_CELL_TIMEOUT_S) -> str:
    job = BoundaryJob(uuid.uuid4().hex[:12], grid, J, records_per_period, seed, beta_ladder,
                      attack_budget_s, timeout_s)
    _JOBS[job.job_id] = job
    job.save()
    job.thread = threading.Thread(target=job.run, name=f"boundary-{job.job_id}", daemon=True)
    job.thread.start()
    return job.job_id


def job_snapshot(job_id: str) -> Optional[dict]:
    job = _JOBS.get(job_id)
    if job is not None:
        return jsonable(job.snapshot())
    path = RESULTS_DIR / f"boundary_{job_id}.json"
    return json.loads(path.read_text()) if path.exists() else None


def list_jobs() -> list[dict]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    for path in sorted(RESULTS_DIR.glob("boundary_*.json"), reverse=True):
        try:
            d = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        out.append({k: d.get(k) for k in ("job_id", "status", "done", "total", "config")})
    return out
