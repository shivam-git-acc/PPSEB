"""PATCH 13 — fast (n, q) sweep: correctness-gated, both attacks per cell.

For each (n, q): derive m = 2n*ceil(log2 q), build the honest doctor's frozen
chain and gate it on correctness, then run
  Attack 1 (public-key only): BKZ on a kernel basis computed from pk alone,
  Attack 2 (stolen key):      R^-1 . sk_J, BKZ-reduced (the forward-security attack),
and a negative control, and assign a verdict in which a public-key break
supersedes a stolen-key one.

Deviations from PATCH 13 as written, each measured before being made:
- q = 4001 replaces 4099. The patch says the existing H2 handles its grid, but
  x^n - c is never irreducible when 4 | n and q = 3 (mod 4); 4099 = 3 (mod 4),
  so every n=4 and n=8 cell would be "n/a (H2)". 4001 is prime, 12-bit,
  4001 = 1 (mod 8), and gives the m = 96 (n=4) the patch expected. 4099 is
  still accepted and reported honestly as n/a (H2).
- The negative control. Read literally ("BKZ'd garbage basis"), garbage is the
  kernel basis of pk_i -- and BKZ'd, that IS Attack 1, so the control would
  fail exactly when Attack 1 breaks and "BROKEN (public-key only)" could never
  be reported. Unreduced garbage never reaches the search at all (it fails the
  norm gate), so it can't fail either. The control here is a BKZ-reduced basis
  of an UNRELATED random lattice, used to build a genuine trapdoor for the
  same keyword and searched against the frozen CT_i: a short, well-formed
  trapdoor that reaches Verify but is not bound to pk_i, so it must not return
  the doctor's N0.
- The honest word-basis-vs-threshold check is reported per cell but not gated
  (see GATE_CHECKS): it is PATCH 09's known-wrong check, and gating on it
  made every cell "n/a (honest incorrect)" although the honest search and
  decryption succeed.
- The per-cell timeout defaults to 1 hour, not ~90s (see DEFAULT_CELL_TIMEOUT_S).
- Timeouts are labelled "untested (timeout)", never "secure": an unrun cell
  says nothing about security, and the conclusion never counts it.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
import random
import threading
import time
import traceback
import uuid
from pathlib import Path
from typing import Optional

import numpy as np

from ppseb.hashes import H2, H2_inverse
from ppseb.linalg import gram_schmidt_norm, kernel_basis_mod_q, mat_mod_mixed, strong_reduce
from ppseb.params import Params, derived_m, default_params
from ppseb.scheme import trapdoor
from ppseb.trace import jsonable

from .end_to_end import attack_period, build_frozen_history, verify_search, _test_candidate

DEFAULT_N_VALUES = (4, 8)
DEFAULT_Q_VALUES = (257, 1153, 4001)
DEFAULT_J = 4
DEFAULT_REPEATS = 2
DEFAULT_RECORDS_PER_PERIOD = 40
# PATCH 13 suggests ~90s. Measured with its own settings (J=4, 2 repeats, 40
# records/period): n=4 cells take 96-285s, and n=8 histories alone took ~300s per
# repeat before any attack. A 90s default would time out every cell.
DEFAULT_CELL_TIMEOUT_S = 3600.0

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"

VERDICT_H2 = "n/a (H2)"
VERDICT_HONEST = "n/a (honest incorrect)"
VERDICT_UNTRUSTED = "untrusted"
VERDICT_PK = "BROKEN (public-key only)"
VERDICT_STOLEN = "forward-security break (stolen key)"
VERDICT_FAILED = "attack failed (secure vs these attacks)"
VERDICT_TIMEOUT = "untested (timeout)"
VERDICT_ERROR = "error"

# `word_usable` (honest word basis < usability threshold) is recorded but NOT gated.
# PATCH 13 lists it, but it is the check PATCH 09 identified as wrong: it compares a
# word basis to the period-basis threshold. Measured at n=4, q=257, it fails at every
# period (word_gs 44-64 vs threshold 35) while the honest doctor's search and
# decryption with that same word basis succeed -- gating on it made every cell n/a.
GATE_CHECKS = ("kernel_ok", "match_ok", "nonmatch_ok", "search_ok", "decrypt_ok", "period_usable")


def _stable_seed(*parts) -> int:
    return int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest()[:4], "big")


def m_checks(n: int, q: int, m: int) -> dict:
    """The per-cell m gate: m is derived from THIS cell's (n, q), never cached."""
    expected = 2 * n * math.ceil(math.log2(q))
    return {
        "m": m,
        "m_expected": expected,
        "m_matches_formula": m == expected,
        "m_lower_bound": 2 * n * math.log2(q),
        "m_above_lower_bound": m >= 2 * n * math.log2(q),
    }


def h2_valid(n: int, q: int) -> Optional[str]:
    """None if H2 works at (n, q), else the reason it doesn't."""
    p = Params(n=n, q=q, sigma=4.0, l=10, m=0)
    try:
        b1, b2 = H2("__probe_a__", 0, p), H2("__probe_b__", 0, p)
        H2_inverse(((b1 - b2) % q).astype(np.int64), q)
    except Exception as e:  # noqa: BLE001 -- surfaced as the cell's n/a reason
        return f"{type(e).__name__}: {e}"
    return None


def attack_public_key_only(history, i: int, params: Params, mu, u_pke) -> dict:
    """Attack 1: no secret at all. A kernel basis of pk_i (computable by anyone,
    including the q*e_j vectors), BKZ-reduced, used as the trapdoor."""
    basis, method = strong_reduce(kernel_basis_mod_q(history[i].pk_ri, params.q))
    membership = bool(np.all(mat_mod_mixed(history[i].pk_ri, basis, params.q) == 0))
    return _test_candidate(
        history, i, basis, params, mu, u_pke, source_label="public_key_only",
        membership_ok=membership, reduced_norm=gram_schmidt_norm(basis),
        reducer_method=method, rng_tag="public_key_only",
    )


def negative_control_unrelated_key(history, i: int, params: Params, mu, seed: int) -> dict:
    """A genuine short trapdoor for the right keyword, but for an unrelated random
    lattice, searched against the frozen CT_i. Returning the doctor's N0 would mean
    Verify accepts trapdoors not bound to pk_i -- the search test is not discriminating."""
    q = params.q
    rng = np.random.default_rng(_stable_seed(seed, i, "control_matrix"))
    pyrng = random.Random(_stable_seed(seed, i, "control_sampler"))
    A_unrelated = rng.integers(0, q, size=(params.n, params.m)).astype(np.int64)
    basis, _method = strong_reduce(kernel_basis_mod_q(A_unrelated, q))
    kw = history[i].legit_trap_demo["keyword"]
    trap = trapdoor(A_unrelated, basis, kw, i, mu, params, pyrng)
    N0_star = verify_search(history[i].CT, trap, params)
    N0_legit = history[i].legit_trap_demo["N0"]
    return {
        "N0_legit": N0_legit,
        "N0_star": N0_star,
        "passed": bool(N0_star is not None and N0_star == N0_legit),
        "basis_gs": gram_schmidt_norm(basis),
    }


def run_repeat(n: int, q: int, J: int, records_per_period: int, seed: int) -> dict:
    base = default_params()
    p = Params(n=n, q=q, sigma=base.sigma, l=base.l, usability_C=base.usability_C, m=0)
    record = {"seed": seed, **m_checks(n, q, p.m)}

    history, _stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(
        J, p, seed=seed, records_per_period=records_per_period,
        honest_checks=True, max_seed_retries=0,
    )
    periods = []
    for entry in history:
        checks = entry.legit_trap_demo["checks"]
        periods.append({"period": entry.period, "checks": checks,
                        "gate_ok": all(checks[c] for c in GATE_CHECKS)})
    gate_ok = record["m_matches_formula"] and record["m_above_lower_bound"] and all(
        pe["gate_ok"] for pe in periods)
    record["gate_ok"] = gate_ok
    record["threshold"] = periods[0]["checks"]["threshold"] if periods else None

    if gate_ok:
        for pe in periods:
            i = pe["period"]
            a1 = attack_public_key_only(history, i, p, mu, u_pke)
            a2 = attack_period(history, i, J, stolen_sk, p, mu, u_pke, reducer=strong_reduce)
            ctrl = negative_control_unrelated_key(history, i, p, mu, seed)
            pe["attack1"] = {"N0_legit": a1["N0_legit"], "N0_star": a1["N0_star"],
                             "break": a1["level2_search_break"], "gs_norm": a1["gs_norm"]}
            pe["attack2"] = {"N0_legit": a2["N0_legit"], "N0_star": a2["N0_star"],
                             "break": a2["level2_search_break"], "gs_norm": a2["gs_norm"]}
            pe["control"] = ctrl
    record["periods"] = periods
    return record


def cell_verdict(cell: dict) -> str:
    """PATCH 13 §1.6, applied in order. Attacks never count for a cell whose
    honest chain failed the gate, and a public-key break supersedes a stolen-key one."""
    if cell.get("h2_error"):
        return VERDICT_H2
    if cell.get("timed_out"):
        return VERDICT_TIMEOUT
    if cell.get("error"):
        return VERDICT_ERROR
    repeats = cell.get("repeats") or []
    if not repeats or not all(r["gate_ok"] for r in repeats):
        return VERDICT_HONEST
    periods = [pe for r in repeats for pe in r["periods"]]
    if any(pe["control"]["passed"] for pe in periods):
        return VERDICT_UNTRUSTED
    if any(pe["attack1"]["break"] for pe in periods):
        return VERDICT_PK
    if any(pe["attack2"]["break"] for pe in periods):
        return VERDICT_STOLEN
    return VERDICT_FAILED


def run_cell(n: int, q: int, J: int, repeats: int, records_per_period: int, seed_base: int) -> dict:
    started = time.time()
    m = derived_m(n, q)
    cell = {"n": n, "q": q, "m": m, "J": J, "records_per_period": records_per_period, **m_checks(n, q, m)}
    reason = h2_valid(n, q)
    if reason:
        cell["h2_error"] = reason
    else:
        cell["repeats"] = []
        for rep in range(repeats):
            seed = seed_base + _stable_seed(n, q, rep) % 100_000
            cell["repeats"].append(run_repeat(n, q, J, records_per_period, seed))
    cell["runtime_s"] = time.time() - started
    cell["verdict"] = cell_verdict(cell)
    return cell


def run_cell_with_timeout(n, q, J, repeats, records_per_period, seed_base, timeout_s) -> dict:
    """One cell per subprocess, so the per-cell timeout can actually stop a
    running BKZ (a thread cannot be interrupted mid-reduction).

    Plain subprocess, NOT multiprocessing: spawn and forkserver both hand the
    child the parent's __main__ path, which is "<stdin>" under `python - <<EOF`
    (every cell of a real grid run died on that) and uvicorn's entry script
    under the server. See attacks/nq_cell_worker.py.
    """
    from . import nq_cell_worker

    args = json.dumps({"n": n, "q": q, "J": J, "repeats": repeats,
                       "records_per_period": records_per_period, "seed_base": seed_base})
    cmd = [sys.executable, "-m", "attacks.nq_cell_worker", args]
    started = time.time()
    m = derived_m(n, q)
    base = {"n": n, "q": q, "m": m, "J": J, "records_per_period": records_per_period, **m_checks(n, q, m)}
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout_s,
            cwd=str(Path(__file__).resolve().parent.parent),
        )
    except subprocess.TimeoutExpired:
        cell = {**base, "timed_out": True, "runtime_s": time.time() - started}
        cell["verdict"] = cell_verdict(cell)
        return cell

    line = next((ln for ln in proc.stdout.splitlines() if ln.startswith(nq_cell_worker.MARKER)), None)
    if line is None:
        detail = (proc.stderr or proc.stdout or "worker produced no output").strip()
        cell = {**base, "error": detail[-2000:], "runtime_s": time.time() - started}
        cell["verdict"] = cell_verdict(cell)
        return cell
    return json.loads(line[len(nq_cell_worker.MARKER):])


# --------------------------------------------------------------------------
# Conclusion + job
# --------------------------------------------------------------------------

def build_conclusion(cells: list[dict], n_values, q_values) -> str:
    def where(verdict):
        return [f"(n={c['n']}, q={c['q']})" for c in cells if c["verdict"] == verdict]

    pk, stolen, failed = where(VERDICT_PK), where(VERDICT_STOLEN), where(VERDICT_FAILED)
    timeout, honest, h2 = where(VERDICT_TIMEOUT), where(VERDICT_HONEST), where(VERDICT_H2)
    untrusted, errors = where(VERDICT_UNTRUSTED), where(VERDICT_ERROR)
    valid = [c for c in cells if c["verdict"] in (VERDICT_PK, VERDICT_STOLEN, VERDICT_FAILED)]

    parts = [f"Over n∈{list(n_values)}, q∈{list(q_values)} (m = 2n·⌈log2 q⌉ derived per cell)."]
    if not valid:
        parts.append("No cell passed the correctness gate and completed, so nothing can be concluded "
                     "about either attack.")
    if pk:
        parts.append(f"The public-key-only attack breaks {', '.join(pk)}; the stolen key adds nothing "
                     f"there, since no secret was needed.")
    if stolen:
        parts.append(f"Only the stolen-key attack breaks {', '.join(stolen)} -- a forward-security break "
                     f"at those cells.")
    if failed:
        parts.append(f"Both attacks fail at {', '.join(failed)}.")
    if honest:
        parts.append(f"The honest doctor failed the correctness gate at {', '.join(honest)}, so no attack "
                     f"is reported there.")
    if h2:
        parts.append(f"H2 has no valid construction at {', '.join(h2)}.")
    if untrusted:
        parts.append(f"The negative control passed at {', '.join(untrusted)} (untrusted).")
    if timeout:
        parts.append(f"{', '.join(timeout)} timed out and are untested -- not evidence of security.")
    if errors:
        parts.append(f"{', '.join(errors)} errored.")
    parts.append("Demo-scale q; this says nothing about asymptotic security.")
    return " ".join(parts)


class NqJob:
    def __init__(self, job_id, n_values, q_values, J, repeats, records_per_period, seed_base, timeout_s):
        self.job_id = job_id
        self.config = {"n_values": list(n_values), "q_values": list(q_values), "J": J, "repeats": repeats,
                       "records_per_period": records_per_period, "seed_base": seed_base,
                       "cell_timeout_s": timeout_s}
        self.cells: list[dict] = []
        self.status = "running"
        self.started_at = time.time()
        self.thread: Optional[threading.Thread] = None

    def path(self) -> Path:
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        return RESULTS_DIR / f"nq_{self.job_id}.json"

    def snapshot(self) -> dict:
        cfg = self.config
        total = len(cfg["n_values"]) * len(cfg["q_values"])
        return {
            "job_id": self.job_id, "status": self.status, "config": cfg,
            "done": len(self.cells), "total": total,
            "elapsed_s": time.time() - self.started_at, "cells": self.cells,
            "conclusion": build_conclusion(self.cells, cfg["n_values"], cfg["q_values"]) if self.cells else None,
        }

    def save(self) -> None:
        tmp = self.path().with_suffix(".json.tmp")
        tmp.write_text(json.dumps(jsonable(self.snapshot()), indent=2))
        tmp.replace(self.path())

    def run(self) -> None:
        try:
            cfg = self.config
            for n in cfg["n_values"]:
                for q in cfg["q_values"]:
                    self.cells.append(run_cell_with_timeout(
                        n, q, cfg["J"], cfg["repeats"], cfg["records_per_period"], cfg["seed_base"],
                        cfg["cell_timeout_s"]))
                    self.save()
            self.status = "done"
        except Exception as e:  # noqa: BLE001
            self.status = f"failed: {type(e).__name__}: {e}"
        self.save()


_JOBS: dict[str, NqJob] = {}


def start_job(n_values=DEFAULT_N_VALUES, q_values=DEFAULT_Q_VALUES, J=DEFAULT_J, repeats=DEFAULT_REPEATS,
              records_per_period=DEFAULT_RECORDS_PER_PERIOD, seed_base=1300,
              timeout_s=DEFAULT_CELL_TIMEOUT_S) -> str:
    job = NqJob(uuid.uuid4().hex[:12], n_values, q_values, J, repeats, records_per_period, seed_base, timeout_s)
    _JOBS[job.job_id] = job
    job.save()
    job.thread = threading.Thread(target=job.run, name=f"nq-{job.job_id}", daemon=True)
    job.thread.start()
    return job.job_id


def job_snapshot(job_id: str) -> Optional[dict]:
    job = _JOBS.get(job_id)
    if job is not None:
        return jsonable(job.snapshot())
    path = RESULTS_DIR / f"nq_{job_id}.json"
    if path.exists():
        return json.loads(path.read_text())
    return None


def list_jobs() -> list[dict]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    for path in sorted(RESULTS_DIR.glob("nq_*.json"), reverse=True):
        try:
            d = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        out.append({k: d.get(k) for k in ("job_id", "status", "done", "total", "config")})
    return out
