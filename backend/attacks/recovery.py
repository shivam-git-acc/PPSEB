"""PATCH 19 — what actually decides break vs no-break.

The per-period displays reported the attack basis's Gram-Schmidt norm, and it
does not predict recovery: a basis at GS 6.08 recovered while one at GS 5.33
did not. That is not noise in the measurement, it is the wrong variable. The
GS norm is a DISTRIBUTIONAL bound on what SamplePre will produce; what goes
into Verify is one REALIZED trapdoor vector, and whether Verify decodes is
decided by how much room that vector leaves inside the q/4 threshold.

So this module measures, for every trapdoor the attacker tests:

    trap_norm     ||Trap|| of the realized sampled vector
    decode_margin q/4 - max_i dist(y_i, q/2), where y = CT1 - Trap^T.CT2
                  (positive => Verify decodes => a match is possible)
    basis_gs      the old proxy, kept precisely to show it does NOT predict
    recovered     the unchanged success criterion: the search returned the
                  doctor's own N0 on the frozen database

Sampling noise is killed rather than averaged over in prose: many records per
period, many trapdoor samples per (period, keyword), and several independent
rebuilds. A period then has a recovery RATE, which is a smooth, plottable
quantity, instead of one coin flip.

`decode_margin` mirrors ppseb.scheme.verify exactly, including its wrap-around
distance -- PATCH 19 writes |y_i - q/2|, but Verify uses
min(|y_i - q/2|, q - |y_i - q/2|), and a margin that disagreed with the
function it claims to explain would be worthless. The identity
`margin > 0 <=> verify() matches` is asserted, not assumed (test_margin_agrees).

Honesty, unchanged: same-N0 success on a frozen database, the negative control
must fail, and a rate is reported for what was measured -- never extrapolated
past the parameters it was measured at.
"""

from __future__ import annotations

import hashlib
import math
import random
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np

from ppseb.linalg import (gram_schmidt_norm, kernel_basis_mod_q, mat_mod_mixed, safe_matmul,
                          strong_reduce)
from ppseb.params import Params, default_params
from ppseb.scheme import trapdoor, verify
from ppseb.trace import Trace

from .end_to_end import build_frozen_history, verify_search, _recover_period_candidate

SAMPLES = 50                 # trapdoor draws per (attack, repeat, period)
RECORDS_PER_PERIOD = 30      # enough targets that a period's rate is not a coin flip
REPEATS = 3                  # independent rebuilds, to average out database luck
DEFAULT_J = 2
DEFAULT_SEED = 1900
DEMO_BETA = 2
# The attacker's own sampling width, as a multiple of the scheme's sigma. The
# point of the sweep (PATCH 19 §4): as sigma grows, ||Trap|| grows, the margin
# shrinks, and the recovery rate should fall smoothly from 1 to 0.
SIGMA_SCALES = (0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 4.0, 6.0)
ATTACKS = ("public_key", "stolen_key")


def decode_margin(CT1: np.ndarray, CT2: np.ndarray, trap: np.ndarray, params: Params) -> float:
    """q/4 minus the worst coordinate's distance from q/2 -- positive exactly
    when ppseb.scheme.verify accepts. This is the continuous quantity behind
    Verify's boolean."""
    q = params.q
    y = (CT1 - safe_matmul(trap, CT2)) % q
    half_q = q // 2
    dist = np.minimum(np.abs(y - half_q), q - np.abs(y - half_q))
    return float(q // 4 - int(np.max(dist)))


@dataclass
class Cell:
    """One (attack, repeat, period): a fixed basis, sampled many times."""
    attack: str
    repeat: int
    period: int
    basis_gs: float
    sigma_scale: float


def _stable_rng(*parts) -> random.Random:
    return random.Random(int.from_bytes(hashlib.sha256("|".join(map(str, parts)).encode()).digest()[:4], "big"))


def _attacker_basis(kind: str, history, i: int, J: int, stolen_sk, params: Params, beta: int):
    """The two attack paths, each producing the basis its attacker can build.
    Both go through the repaired q-ary transform (see the sublattice note in
    forward_sec._recover_candidate)."""
    if kind == "public_key":
        basis, method = strong_reduce(kernel_basis_mod_q(history[i].pk_ri, params.q), block_size=beta)
        return basis, method
    basis, membership, _t, _r, method = _recover_period_candidate(
        history, i, J, stolen_sk, params, reducer=lambda B: strong_reduce(B, block_size=beta))
    if not membership:
        raise RuntimeError("reconstructed basis left L_perp_q(pk_i)")
    return basis, method


def sample_cell(history, i: int, basis: np.ndarray, params: Params, mu: np.ndarray,
                samples: int, rng_tag: str, sigma_scale: float = 1.0) -> list[dict]:
    """`samples` independent trapdoor draws from ONE basis, each measured.

    SamplePre is randomized, so this is the distribution the single-shot
    displays were reporting one draw from.
    """
    kw = history[i].legit_trap_demo["keyword"]
    N0_legit = history[i].legit_trap_demo["N0"]
    if N0_legit is None:
        # The honest doctor's own search failed on this build, so there is no
        # target to measure a margin against and "recovered" has no meaning
        # here. Refused loudly rather than measured against nothing.
        raise RuntimeError(f"period {i}: the honest search found no record, so there is no "
                           f"target to measure recovery against")
    target_ct = next((c1, c2) for (n_id, c1, c2) in history[i].CT if n_id == N0_legit)

    p = Params(n=params.n, q=params.q, sigma=params.sigma * sigma_scale, l=params.l,
               usability_C=params.usability_C, m=0)
    p.ciphertext_noise_sigma = params.ciphertext_noise_sigma

    out = []
    for k in range(samples):
        rng = _stable_rng(rng_tag, i, k, sigma_scale)
        try:
            trap = trapdoor(history[i].pk_ri, basis, kw, i, mu, p, rng)
        except Exception as e:  # noqa: BLE001 -- a draw can fail on a degenerate basis
            out.append({"sample": k, "error": f"{type(e).__name__}: {e}", "recovered": False,
                        "target_match": False, "trap_norm": None, "margin": None})
            continue
        margin = decode_margin(target_ct[0], target_ct[1], trap, p)
        target_match = bool(verify(target_ct[0], target_ct[1], trap, p)[0])
        N0_star = verify_search(history[i].CT, trap, p)
        out.append({
            "sample": k,
            "trap_norm": float(np.linalg.norm(trap.astype(float))),
            "margin": margin,
            "target_match": target_match,
            "recovered": bool(N0_star is not None and N0_star == N0_legit),
            # A different record matching first is a FALSE ACCEPT, and is the
            # only way `recovered` and `target_match` can disagree.
            "false_accept": bool(N0_star is not None and N0_star != N0_legit),
        })
    return out


def _summarise(attempts: list[dict]) -> dict:
    ok = [a for a in attempts if a.get("trap_norm") is not None]
    rec = [a for a in ok if a["recovered"]]
    return {
        "samples": len(attempts),
        "measured": len(ok),
        "recovered": len(rec),
        "recovery_rate": (len(rec) / len(ok)) if ok else None,
        "mean_trap_norm": float(np.mean([a["trap_norm"] for a in ok])) if ok else None,
        "mean_margin": float(np.mean([a["margin"] for a in ok])) if ok else None,
        "false_accepts": sum(1 for a in ok if a.get("false_accept")),
        "errors": len(attempts) - len(ok),
    }


def _quantile_bins(values: list[float], k: int = 8) -> list[tuple[float, float]]:
    if not values:
        return []
    qs = np.quantile(values, np.linspace(0, 1, k + 1))
    qs = sorted(set(round(float(x), 6) for x in qs))
    return [(qs[j], qs[j + 1]) for j in range(len(qs) - 1)] or [(qs[0], qs[0])]


def rate_curve(attempts: list[dict], key: str, k: int = 8) -> list[dict]:
    """Recovery rate against a binned continuous variable -- Plot 1 (and the
    falsifier, Plot 3, with key='basis_gs')."""
    ok = [a for a in attempts if a.get(key) is not None]
    if not ok:
        return []
    bins = _quantile_bins([a[key] for a in ok], k)
    rows = []
    for lo, hi in bins:
        inside = [a for a in ok if lo <= a[key] <= hi]
        if not inside:
            continue
        rows.append({"lo": lo, "hi": hi, "center": (lo + hi) / 2, "n": len(inside),
                     "rate": sum(1 for a in inside if a["recovered"]) / len(inside)})
    return rows


def margin_histograms(attempts: list[dict], bins: int = 24) -> dict:
    """Plot 2: the margin distribution for recovered vs failed attempts. The
    mechanistic claim is that they separate at margin = 0.

    The bins are anchored so that 0 is an EDGE and each bin is left-open,
    right-closed -- `edges[i-1] < v <= edges[i]`. Both details matter, because
    Verify accepts only when the worst coordinate is STRICTLY inside q/4, so a
    margin of exactly 0 is a FAILURE. numpy's default half-open [lo, hi) bins
    put those zeros in the bin starting at 0, which is drawn at its centre --
    i.e. a green "failed" bar appearing to the RIGHT of the margin = 0 line,
    contradicting on screen the very claim the plot exists to support. Zeros
    now land in the bin ending at 0, on the failing side of the line where
    they belong, and `zero_margin` reports how many there were.
    """
    ok = [a for a in attempts if a.get("margin") is not None]
    if not ok:
        return {"bins": [], "recovered": [], "failed": []}
    values = np.array([a["margin"] for a in ok], dtype=float)
    flags = np.array([bool(a["recovered"]) for a in ok])
    lo, hi = float(values.min()), float(values.max())
    step = max((hi - lo) / bins, 1e-9)
    n_neg = int(math.ceil(max(-lo, 0.0) / step))
    n_pos = int(math.ceil(max(hi, 0.0) / step))
    edges = np.array([(-n_neg + j) * step for j in range(n_neg + n_pos + 1)])
    if edges.size < 2:
        edges = np.array([-step, 0.0, step])
    # right=True => edges[i-1] < v <= edges[i], so v == 0 joins the bin below.
    idx = np.digitize(values, edges, right=True)
    idx = np.clip(idx, 1, len(edges) - 1)
    rows = []
    for j in range(1, len(edges)):
        inside = idx == j
        rows.append({"lo": float(edges[j - 1]), "hi": float(edges[j]),
                     "center": float((edges[j - 1] + edges[j]) / 2),
                     "recovered": int(np.sum(inside & flags)),
                     "failed": int(np.sum(inside & ~flags))})
    return {
        "bins": rows,
        "crossing": 0.0,
        "recovered_all_positive": all(a["margin"] > 0 for a in ok if a["recovered"]),
        "failed_all_nonpositive": all(a["margin"] <= 0 for a in ok if not a["recovered"]),
        # The exact mechanistic claim is about the TARGET record: a positive
        # margin is precisely when Verify accepts the doctor's own record.
        # `recovered` can differ from it in one way only -- a decoy matching
        # first (a false accept) -- so that count is reported beside it rather
        # than being allowed to blur the separation.
        "target_match_matches_margin": all((a["margin"] > 0) == a["target_match"] for a in ok),
        "false_accepts": sum(1 for a in ok if a.get("false_accept")),
        "zero_margin": sum(1 for a in ok if a["margin"] == 0),
        "n": len(ok),
    }


def _corr(xs: list[float], ys: list[float]) -> Optional[float]:
    """Pearson correlation, or None when a side has no variance -- which is
    itself a result (e.g. every attempt recovered), not something to paper
    over with a fabricated number."""
    if len(xs) < 3:
        return None
    x, y = np.asarray(xs, dtype=float), np.asarray(ys, dtype=float)
    if x.std() == 0 or y.std() == 0:
        return None
    return float(np.corrcoef(x, y)[0, 1])


def correlations(attempts: list[dict]) -> dict:
    """How well each variable predicts recovery, on the SAME attempts, so the
    comparison is like-for-like."""
    ok = [a for a in attempts if a.get("trap_norm") is not None and a.get("basis_gs") is not None]
    y = [1.0 if a["recovered"] else 0.0 for a in ok]
    out = {
        "n_attempts": len(ok),
        "trap_norm": _corr([-a["trap_norm"] for a in ok], y),
        "margin": _corr([a["margin"] for a in ok], y),
        "basis_gs": _corr([-a["basis_gs"] for a in ok], y),
    }
    t, g = out["trap_norm"], out["basis_gs"]
    out["trap_norm_beats_basis_gs"] = (None if t is None or g is None else bool(abs(t) > abs(g)))
    if out["trap_norm"] is None:
        out["note"] = ("No variance in one of the columns -- with every attempt recovering, "
                       "no variable can be said to predict recovery. The sigma sweep supplies "
                       "the variation these correlations need.")
    return out


def run_recovery_analysis(n: int = 4, q: int = 257, J: int = DEFAULT_J,
                          records_per_period: int = RECORDS_PER_PERIOD,
                          samples: int = SAMPLES, repeats: int = REPEATS,
                          seed: int = DEFAULT_SEED, beta: int = DEMO_BETA,
                          sigma_scales=SIGMA_SCALES, attacks=ATTACKS,
                          build_retries: int = 4, progress=None) -> dict:
    """The whole PATCH 19 measurement: rates, distributions, the falsifier and
    the sigma sweep, all from live runs."""
    started = time.time()
    trace = Trace()
    trace.note(
        "Measuring the variables that decide Verify, not the one that bounds them",
        detail="The attack basis's Gram-Schmidt norm is a distributional bound on what "
               "SamplePre produces. Verify consumes ONE realized trapdoor, and accepts iff "
               "every coordinate of CT1 - Trap^T.CT2 lands within q/4 of q/2. So the realized "
               "||Trap|| and the resulting decode margin are measured per attempt, with the "
               "GS norm kept alongside to show it does not predict the outcome.",
        data={"samples_per_cell": samples, "records_per_period": records_per_period,
              "repeats": repeats, "sigma_scales": list(sigma_scales)},
        algo="Recovery", highlight=True)

    base = default_params()
    cells, attempts, sweep_attempts, skipped, rebuilt = [], [], [], [], []
    total_units = repeats * J * len(attacks)
    unit = 0

    for repeat in range(repeats):
        p = Params(n=n, q=q, sigma=base.sigma, l=base.l, usability_C=base.usability_C, m=0)
        # J frozen periods (0..J-1); the stolen key is period J's, which never
        # appears in `history`. Passing J+1 here would make `stolen_sk` belong
        # to a period the R-product does not reach, and every stolen-key cell
        # would fail its membership check.
        # A noise draw that breaks the HONEST doctor's own search leaves no
        # baseline to measure the attacker against -- a setup failure, not a
        # finding. build_frozen_history has a retry for exactly this, but it
        # hangs off an assertion that `honest_checks=True` suppresses, so it
        # can never fire here; the retry is done explicitly instead, and the
        # seeds it burned are reported rather than hidden.
        history = stolen_sk = mu = None
        attempts_used = []
        for attempt in range(build_retries + 1):
            build_seed = seed + 101 * repeat + 7919 * attempt
            history, _spk, stolen_sk, mu, _u = build_frozen_history(
                J, p, seed=build_seed, records_per_period=records_per_period,
                honest_checks=True, max_seed_retries=0)
            unusable = [h.period for h in history[:J] if h.legit_trap_demo["N0"] is None]
            attempts_used.append({"seed": build_seed, "unusable_periods": unusable})
            if not unusable:
                break
        if unusable:
            skipped.append({"repeat": repeat, "periods": unusable, "builds_tried": attempts_used,
                            "reason": "the honest doctor's own search failed at these periods in "
                                      "every build tried, so there is no working baseline to "
                                      "measure the attacker against"})
            trace.note(f"Repeat {repeat} skipped", detail=skipped[-1]["reason"],
                       data=skipped[-1], algo="Recovery")
            continue
        if len(attempts_used) > 1:
            rebuilt.append({"repeat": repeat, "builds_tried": attempts_used})
            trace.note(f"Repeat {repeat} rebuilt after a failed honest baseline",
                       detail="The doctor's own search failed on the first build(s); rebuilt with "
                              "a fresh seed. The attacker's candidate and success criterion are "
                              "untouched by this.",
                       data=rebuilt[-1], algo="Recovery")
        for kind in attacks:
            for i in range(J):
                unit += 1
                if progress:
                    progress(unit, total_units, f"{kind} repeat {repeat} period {i}")
                try:
                    basis, _method = _attacker_basis(kind, history, i, J, stolen_sk, p, beta)
                except Exception as e:  # noqa: BLE001
                    cells.append({"attack": kind, "repeat": repeat, "period": i,
                                  "error": f"{type(e).__name__}: {e}"})
                    continue
                gs = gram_schmidt_norm(basis)
                on_lattice = bool(np.all(mat_mod_mixed(history[i].pk_ri, basis, q) == 0))
                got = sample_cell(history, i, basis, p, mu, samples,
                                  rng_tag=f"{kind}|{repeat}|{seed}")
                for a in got:
                    a.update(attack=kind, repeat=repeat, period=i, basis_gs=gs, sigma_scale=1.0)
                attempts.extend(got)
                cells.append({"attack": kind, "repeat": repeat, "period": i, "basis_gs": gs,
                              "on_lattice": on_lattice, "honest_gs": history[i].legit_trap_demo["period_gs"],
                              **_summarise(got)})

        # PATCH 19 §4 -- the controlled law. One basis (the public-key one, at
        # period 0 of this repeat), sampled across a range of attacker sigmas.
        if sigma_scales:
            try:
                basis, _m = _attacker_basis("public_key", history, 0, J, stolen_sk, p, beta)
                gs = gram_schmidt_norm(basis)
                for scale in sigma_scales:
                    got = sample_cell(history, 0, basis, p, mu, samples,
                                      rng_tag=f"sweep|{repeat}|{seed}", sigma_scale=scale)
                    for a in got:
                        a.update(attack="sigma_sweep", repeat=repeat, period=0,
                                 basis_gs=gs, sigma_scale=scale)
                    sweep_attempts.extend(got)
            except Exception as e:  # noqa: BLE001
                trace.note("Sigma sweep skipped for this repeat", detail=f"{type(e).__name__}: {e}",
                           algo="Recovery")

    sigma_rows = []
    for scale in sigma_scales:
        got = [a for a in sweep_attempts if a["sigma_scale"] == scale]
        if got:
            sigma_rows.append({"sigma_scale": scale,
                               "sigma": base.sigma * scale, **_summarise(got)})

    all_attempts = attempts + sweep_attempts
    result = {
        "config": {"n": n, "q": q, "J": J, "records_per_period": records_per_period,
                   "samples": samples, "repeats": repeats, "seed": seed, "beta": beta,
                   "sigma_scales": list(sigma_scales), "attacks": list(attacks),
                   "decode_threshold": q // 4},
        "cells": cells,
        "n_attempts": len(all_attempts),
        "plot1_recovery_vs_trap_norm": rate_curve(all_attempts, "trap_norm"),
        "plot2_margin_histograms": margin_histograms(all_attempts),
        "plot3_recovery_vs_basis_gs": rate_curve(all_attempts, "basis_gs"),
        "plot3_cells": [{"basis_gs": c["basis_gs"], "recovery_rate": c["recovery_rate"],
                         "attack": c["attack"], "period": c["period"], "repeat": c["repeat"]}
                        for c in cells if c.get("recovery_rate") is not None],
        "skipped_repeats": skipped,
        "rebuilt_repeats": rebuilt,
        "repeats_measured": len({c["repeat"] for c in cells if c.get("recovery_rate") is not None}),
        "sigma_sweep": sigma_rows,
        "sigma_sweep_monotone": _monotone([r["recovery_rate"] for r in sigma_rows]),
        "correlations_all": correlations(all_attempts),
        "correlations_base_only": correlations(attempts),
        "attempts_sample": all_attempts[:400],
        "runtime_s": time.time() - started,
    }
    result["statement"] = build_statement(result)
    trace.result("Recovery analysis", detail=result["statement"],
                 data={"n_attempts": result["n_attempts"],
                       "correlations": result["correlations_all"]},
                 algo="Recovery", highlight=True)
    result["trace"] = trace.to_list()
    return result


def _monotone(values: list[Optional[float]]) -> Optional[bool]:
    vals = [v for v in values if v is not None]
    if len(vals) < 3:
        return None
    return all(a >= b - 1e-9 for a, b in zip(vals, vals[1:]))


def build_statement(r: dict) -> str:
    """PATCH 19 §5, filled from the measurement -- including the cases where
    the measurement does NOT show what the patch expected."""
    c, corr = r["config"], r["correlations_all"]
    hist = r["plot2_margin_histograms"]
    measured_repeats = r.get("repeats_measured", c["repeats"])
    parts = [
        f"Over {c['records_per_period']} records x {c['samples']} trapdoor samples x "
        f"{measured_repeats} repeat(s) at n={c['n']}, q={c['q']} ({r['n_attempts']} measured "
        f"attempts), recovery was scored against the realized trapdoor norm and the ciphertext "
        f"decode margin rather than the basis Gram-Schmidt norm."]
    if r.get("skipped_repeats"):
        parts.append(
            f"{len(r['skipped_repeats'])} of the {c['repeats']} configured repeats were SKIPPED: "
            f"the honest doctor's own search failed there in every build tried, leaving no "
            f"baseline to measure an attacker against. They contribute nothing to the numbers "
            f"below.")

    if hist.get("target_match_matches_margin"):
        parts.append(
            f"A positive decode margin and Verify accepting the doctor's own record coincide on "
            f"all {hist.get('n')} attempts, with no exceptions: the margin is the deciding line, "
            f"not a correlate of it."
            + ("" if hist.get("recovered_all_positive") and hist.get("failed_all_nonpositive") else
               f" {hist.get('false_accepts')} attempt(s) still scored as not recovered because a "
               f"decoy record matched first -- the only way the two can differ."))
    else:
        parts.append("Recovered and failed attempts do NOT separate cleanly at margin 0 "
                     f"(recovered all positive: {hist.get('recovered_all_positive')}, failed all "
                     f"non-positive: {hist.get('failed_all_nonpositive')}) -- reported as measured.")

    t, g = corr.get("trap_norm"), corr.get("basis_gs")
    if t is not None and g is not None:
        parts.append(
            f"Across the same attempts, recovery correlates with the realized trapdoor norm at "
            f"r={t:+.2f} and with the basis GS norm at r={g:+.2f}"
            + (", so the realized norm is the better predictor by a clear margin."
               if abs(t) > abs(g) else
               ", so on this data the basis norm is NOT out-predicted -- reported as measured."))
    elif corr.get("note"):
        parts.append(corr["note"])

    sweep = r["sigma_sweep"]
    if sweep:
        first, last = sweep[0], sweep[-1]
        shape = ("falls monotonically" if r["sigma_sweep_monotone"] else "falls, though not monotonically")
        parts.append(
            f"Holding the basis fixed and widening only the attacker's sampling sigma, the "
            f"recovery rate {shape} from {first['recovery_rate']:.2f} at sigma={first['sigma']:.1f} "
            f"(mean ||Trap|| {first['mean_trap_norm']:.0f}, mean margin {first['mean_margin']:+.0f}) "
            f"to {last['recovery_rate']:.2f} at sigma={last['sigma']:.1f} "
            f"(mean ||Trap|| {last['mean_trap_norm']:.0f}, mean margin {last['mean_margin']:+.0f}). "
            f"A break occurs exactly when a sampled trapdoor keeps the decode margin positive.")
    parts.append(
        "Measured at demonstration parameters, for this attack family, under the same-N0 success "
        "criterion on a frozen database; it describes the decode mechanics, not the scheme's "
        "asymptotic security.")
    return " ".join(parts)


# --------------------------------------------------------------------------
# Background job — the full-size run takes minutes, so the UI polls it
# --------------------------------------------------------------------------

import json
import threading
import uuid
from pathlib import Path

from ppseb.trace import jsonable

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
_JOBS: dict[str, dict] = {}
_LOCK = threading.Lock()


def _job_path(job_id: str) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR / f"recovery_{job_id}.json"


def start_job(**kwargs) -> str:
    job_id = uuid.uuid4().hex[:12]
    state = {"job_id": job_id, "status": "running", "done": 0, "total": None,
             "stage": "building the frozen databases", "started_at": time.time(),
             "config": {k: v for k, v in kwargs.items() if k != "progress"}, "result": None}
    with _LOCK:
        _JOBS[job_id] = state

    def progress(done, total, stage):
        with _LOCK:
            state.update(done=done, total=total, stage=stage)

    def run():
        try:
            result = run_recovery_analysis(progress=progress, **kwargs)
            with _LOCK:
                state.update(status="done", result=result, elapsed_s=time.time() - state["started_at"])
            _job_path(job_id).write_text(json.dumps(jsonable(state), indent=2))
        except Exception as e:  # noqa: BLE001
            with _LOCK:
                state.update(status=f"failed: {type(e).__name__}: {e}",
                             elapsed_s=time.time() - state["started_at"])

    threading.Thread(target=run, name=f"recovery-{job_id}", daemon=True).start()
    return job_id


def job_snapshot(job_id: str) -> Optional[dict]:
    with _LOCK:
        state = _JOBS.get(job_id)
        if state is not None:
            return jsonable({**state, "elapsed_s": state.get("elapsed_s",
                                                             time.time() - state["started_at"])})
    path = _job_path(job_id)
    return json.loads(path.read_text()) if path.exists() else None


def list_jobs() -> list[dict]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    out = []
    with _LOCK:
        for state in _JOBS.values():
            out.append({k: state.get(k) for k in ("job_id", "status", "done", "total", "config")})
    known = {row["job_id"] for row in out}
    for path in sorted(RESULTS_DIR.glob("recovery_*.json"), reverse=True):
        try:
            d = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if d.get("job_id") not in known:
            out.append({k: d.get(k) for k in ("job_id", "status", "done", "total", "config")})
    return out
