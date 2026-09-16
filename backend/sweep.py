"""PATCH 08 — batch sweep: run the end-to-end forward-security attack over a
grid of configurations UNATTENDED, checkpointing to disk, then aggregate into
publication plots and a written conclusion.

Design notes that matter for correctness (not just plumbing):

**The trust gate.** PATCH 08 says "reuses PATCH-07 per-cell trust gates", but
there is no PATCH-07 in this repo. Rather than invent a gate, the gate here is
assembled from PATCH 08's OWN stated guardrails (§ header): a repeat is
TRUSTED only if it completed, its negative controls all FAILED (garbage and
wrong-period keys did not pass Level 2), and the independent word-basis
cross-check AGREED with the measured Level 2 outcome at every period. Anything
else is untrusted and is excluded from the conclusion — never silently counted
as "survives". See `record_is_trusted`.

**That strict gate is measurably biased, so it is not the only view.** The
word-basis predictor reuses the PERIOD-basis usability threshold on the WORD
basis (PATCH 06 §6.5 forbade inventing a new one), but the extra delegation
inflates the norm past it: in a live run the honest doctor's own word basis
was over threshold in 4 of 5 frozen periods, yet the honest search worked in
every one (the history build asserts it). A predictor that rejects bases which
demonstrably work can only "agree" with a non-break, so "must agree" filters
out genuine breaks and biases an unattended sweep toward "no break found".
Because every raw field is checkpointed, the gate is applied at AGGREGATION
time: "strict" (the patch as written, still the default headline) and
"controls_only" can both be read after the run without re-running anything.
`gate_diagnostics` measures the miscalibration and lists every break excluded
solely by the word-basis condition, and the conclusion refuses to call a run
a "consistent negative result" when that list is non-empty.

**Seeds use a stable digest, never `hash()`.** Python randomizes string hashing
per process, so `hash()`-derived seeds change on every restart -- which would
change every idempotency key and turn "resume" into "re-run and double-count".
Resume is also guarded by a per-job lock (one owning process) and read-side
de-duplication by key.

**Why a thread is safe here.** `linalg.strong_reduce` reaches fpylll, whose
cysignals dependency can only install signal handlers on the MAIN thread — a
background worker that imports it first raises `ValueError: signal only works
in main thread`. `warm_up_native_libs()` performs that import once on the main
thread (called at API import time) so the worker thread only ever hits the
already-cached `sys.modules` entry. Verified empirically before this module
was built; without the warm-up every BKZ cell in the sweep would die.

**The H2 dimension constraint is a real, pre-flight-visible cost.** H2's
twisted-binomial construction only exists for n whose every prime factor
divides q-1 (Lidl-Niederreiter). For the default q=257 (q-1 = 2^8) that means
n must be a power of two, so PATCH 08's suggested default grid
(n in {4, 6, 8, 10}) has HALF its cells guaranteed to error — not a random
risk, a certainty. `preflight()` reports exactly which cells are doomed and
why BEFORE a night is spent on them, rather than discovering it at breakfast.
The defaults still match the patch; the warning is what's new.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Iterator, Optional

from ppseb.params import Params, default_params
from attacks.end_to_end import end_to_end_experiment, RECORDS_PER_PERIOD

RESULTS_DIR = Path(__file__).resolve().parent / "results"

# Rough per-period cost used only for the ETA shown before launch (PATCH 08
# §2 cites PATCH 03's measured timings). Deliberately approximate — it exists
# so the user knows "this is an overnight job", not to be precise.
_ETA_SECONDS_PER_PERIOD = {4: 3.0, 6: 12.0, 8: 38.0, 10: 120.0, 16: 600.0}


def eta_seconds_per_period(n: int) -> float:
    if n in _ETA_SECONDS_PER_PERIOD:
        return _ETA_SECONDS_PER_PERIOD[n]
    known = sorted(_ETA_SECONDS_PER_PERIOD)
    if n < known[0]:
        return _ETA_SECONDS_PER_PERIOD[known[0]]
    # Extrapolate from the largest measured point, scaling steeply with n.
    biggest = known[-1]
    return _ETA_SECONDS_PER_PERIOD[biggest] * (n / biggest) ** 3


def warm_up_native_libs() -> bool:
    """Import fpylll on whatever thread calls this — MUST be the main thread.

    cysignals installs signal handlers at import time and raises on a
    non-main thread. Doing it once here means the sweep's worker thread
    only ever sees the cached sys.modules entry. Returns whether fpylll is
    actually available (False is fine — the sweep then runs with the plain
    LLL fallback, reported honestly per cell via `reducer_method`).
    """
    try:
        import fpylll  # noqa: F401
        return True
    except Exception:  # noqa: BLE001 -- ImportError, or cysignals' ValueError
        return False


# --------------------------------------------------------------------------
# Config + grid
# --------------------------------------------------------------------------

@dataclass
class SweepConfig:
    """PATCH 08 §2's grid. Defaults are the patch's own overnight defaults."""
    n_values: list[int] = field(default_factory=lambda: [4, 6, 8, 10])
    J_values: list[int] = field(default_factory=lambda: [3, 4, 5, 6, 8])
    h1_variants: list[str] = field(default_factory=lambda: ["low_norm"])
    reducers: list[str] = field(default_factory=lambda: ["bkz"])
    records_per_period: int = RECORDS_PER_PERIOD
    repeats: int = 3
    seed_base: int = 1000
    max_hours: float = 12.0

    def cells(self) -> Iterator[tuple[int, int, str, str]]:
        for variant in self.h1_variants:
            for reducer in self.reducers:
                for n in self.n_values:
                    for J in self.J_values:
                        yield (n, J, variant, reducer)

    def units(self) -> Iterator[tuple[int, int, str, str, int, int]]:
        """Every (cell, repeat) unit of work, with its deterministic seed."""
        for (n, J, variant, reducer) in self.cells():
            for repeat in range(self.repeats):
                yield (n, J, variant, reducer, repeat, self.seed_for(n, J, variant, reducer, repeat))

    def seed_for(self, n: int, J: int, variant: str, reducer: str, repeat: int) -> int:
        """Deterministic per-unit seed: reproducible, and different across
        repeats so a repeat is a genuinely independent draw (PATCH 08 §5).

        Uses a stable digest, NOT Python's built-in hash(): string hashing is
        randomized per process (PYTHONHASHSEED), which would give every unit a
        new seed -- and so a new idempotency key -- after a server restart,
        silently turning "resume" into "re-run and double-count"."""
        digest = hashlib.sha256(f"{n}|{J}|{variant}|{reducer}|{repeat}".encode()).digest()
        return self.seed_base + int.from_bytes(digest[:4], "big") % 100_000


def unit_key(n: int, J: int, variant: str, reducer: str, repeat: int, seed: int) -> str:
    """Idempotency key (PATCH 08 §3): re-running never double-counts."""
    return f"n{n}|J{J}|{variant}|{reducer}|r{repeat}|s{seed}"


def h2_dimension_valid(n: int, q: int) -> bool:
    """H2's twisted binomial x^n - c exists only when every prime factor of
    n divides q-1 (Lidl-Niederreiter). Checked directly rather than by
    trial-and-error so preflight can explain WHY a cell is doomed."""
    if n < 1:
        return False
    remaining, f = n, 2
    factors = set()
    while f * f <= remaining:
        while remaining % f == 0:
            factors.add(f)
            remaining //= f
        f += 1
    if remaining > 1:
        factors.add(remaining)
    return all((q - 1) % p == 0 for p in factors)


def preflight(config: SweepConfig, q: int) -> dict:
    """What this grid will actually cost, and which cells are already doomed.

    Run BEFORE launching so an overnight job isn't spent on cells that
    cannot possibly succeed at this q (see the module docstring).
    """
    invalid_n = [n for n in config.n_values if not h2_dimension_valid(n, q)]
    valid_n = [n for n in config.n_values if n not in invalid_n]

    total_units = sum(1 for _ in config.units())
    doomed_units = sum(
        1 for (n, _J, _v, _r, _rep, _s) in config.units() if n in invalid_n
    )

    eta_s = 0.0
    for (n, J, _variant, _reducer, _repeat, _seed) in config.units():
        if n in invalid_n:
            continue
        # Each period costs a build step plus an attack plus two negative
        # controls plus the word-basis cross-check -- call it ~3x a bare
        # per-period attack, which is what the cited timings measured.
        eta_s += eta_seconds_per_period(n) * J * 3.0

    return {
        "total_cells": sum(1 for _ in config.cells()),
        "total_units": total_units,
        "runnable_units": total_units - doomed_units,
        "doomed_units": doomed_units,
        "invalid_n": invalid_n,
        "valid_n": valid_n,
        "q": q,
        "eta_seconds": eta_s,
        "eta_hours": eta_s / 3600.0,
        "warnings": (
            [
                f"n={invalid_n} have no valid H2 for q={q}: every prime factor of n must "
                f"divide q-1={q - 1}, so only powers of 2 work here. Those {doomed_units} "
                f"of {total_units} units WILL error — they are excluded from the ETA above. "
                f"Drop them (use n={valid_n}) unless you specifically want the failure "
                f"recorded."
            ]
            if invalid_n
            else []
        ),
    }


# --------------------------------------------------------------------------
# Persistence (PATCH 08 §3)
# --------------------------------------------------------------------------

def params_to_dict(p: Params) -> dict:
    return {"n": p.n, "q": p.q, "sigma": p.sigma, "l": p.l, "usability_C": p.usability_C}


def params_from_dict(d: dict) -> Params:
    return Params(n=d["n"], q=d["q"], sigma=d["sigma"], l=d["l"], usability_C=d["usability_C"], m=0)


def _paths(job_id: str) -> tuple[Path, Path]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return (RESULTS_DIR / f"sweep_{job_id}.jsonl", RESULTS_DIR / f"sweep_{job_id}.meta.json")


def write_meta(job_id: str, meta: dict) -> None:
    _jsonl, meta_path = _paths(job_id)
    tmp = meta_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(meta, indent=2))
    tmp.replace(meta_path)  # atomic: a crash mid-write can't corrupt the meta


def load_meta(job_id: str) -> Optional[dict]:
    _jsonl, meta_path = _paths(job_id)
    if not meta_path.exists():
        return None
    try:
        return json.loads(meta_path.read_text())
    except json.JSONDecodeError:
        return None


def append_record(job_id: str, record: dict) -> None:
    """One line per completed (cell, repeat) — appended as it finishes, so a
    crash loses at most the in-flight unit (PATCH 08 §3)."""
    jsonl_path, _meta = _paths(job_id)
    with jsonl_path.open("a") as fh:
        fh.write(json.dumps(record) + "\n")
        fh.flush()


def load_records(job_id: str) -> list[dict]:
    """Read back every completed unit. Tolerates a torn final line (a crash
    mid-append) rather than refusing to load the whole night's work, and
    de-duplicates by idempotency key (first write wins) so a unit that was
    somehow run twice can never be counted twice."""
    jsonl_path, _meta = _paths(job_id)
    if not jsonl_path.exists():
        return []
    records = []
    seen: set[str] = set()
    for line in jsonl_path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        key = record.get("key")
        if key in seen:
            continue
        seen.add(key)
        records.append(record)
    return records


def _lock_path(job_id: str) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR / f"sweep_{job_id}.lock"


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def acquire_job_lock(job_id: str) -> bool:
    """One process owns a running job. Without this, two server processes
    sharing results/ (e.g. a --reload dev server plus a second instance)
    would both resume the same job and append the same units."""
    path = _lock_path(job_id)
    if path.exists():
        try:
            pid = int(path.read_text().strip())
        except ValueError:
            pid = -1
        if pid > 0 and pid != os.getpid() and _pid_alive(pid):
            return False
    path.write_text(str(os.getpid()))
    return True


def release_job_lock(job_id: str) -> None:
    path = _lock_path(job_id)
    try:
        if path.exists() and path.read_text().strip() == str(os.getpid()):
            path.unlink()
    except OSError:
        pass


def list_jobs() -> list[dict]:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    jobs = []
    for meta_path in sorted(RESULTS_DIR.glob("sweep_*.meta.json"), reverse=True):
        try:
            meta = json.loads(meta_path.read_text())
        except json.JSONDecodeError:
            continue
        jobs.append({
            "job_id": meta.get("job_id"),
            "status": meta.get("status"),
            "started_at": meta.get("started_at"),
            "done": meta.get("done", 0),
            "total": meta.get("total", 0),
            "config": meta.get("config"),
        })
    return jobs


# --------------------------------------------------------------------------
# The trust gate (see module docstring)
# --------------------------------------------------------------------------

GATES = ("strict", "controls_only")


def record_is_trusted(record: dict, gate: str = "strict") -> bool:
    """PATCH 08's guardrails, applied per repeat. A repeat counts toward a
    verdict ONLY if all of these hold; otherwise it is untrusted and is
    excluded from the conclusion entirely (never counted as "survives").

    gate="strict" is PATCH 08 as written: negative controls must fail AND the
    word-basis cross-check must agree. gate="controls_only" drops the second
    condition. Both are computed from the stored record at aggregation time,
    so either can be read in the morning without re-running anything -- see
    `gate_diagnostics` for why the choice matters.
    """
    if gate not in GATES:
        raise ValueError(f"gate must be one of {GATES}")
    if record.get("status") != "ok":
        return False
    if not record.get("control_ok", False):
        return False
    if gate == "strict" and record.get("wordpred_disagreements"):
        return False
    return True


def gate_diagnostics(records: list[dict]) -> dict:
    """Measure whether the strict gate's word-basis condition is biased.

    The word-basis predictor applies the PERIOD-basis usability threshold to
    the WORD basis (PATCH 06 §6.5 said not to invent a new one). But the
    honest doctor's own search provably works at every frozen period (the
    history build asserts it), so a calibrated predictor should call the
    honest word basis usable essentially always. `honest_word_usable_rate`
    measures that directly. If it is low, "word-basis must agree" can only
    ever agree with a NON-break, and every genuine break gets filtered out
    as untrusted -- biasing an unattended sweep toward "no break found".
    `breaks_excluded_by_wordpred_only` counts exactly the units that would
    have been reported as breaks under the negative controls alone.
    """
    honest_total = 0
    honest_usable = 0
    excluded = []
    for r in records:
        if r.get("status") != "ok":
            continue
        for p in r.get("periods", []):
            hw, thr = p.get("honest_word_gs"), p.get("threshold")
            if hw is None or thr is None:
                continue
            honest_total += 1
            if hw <= thr:
                honest_usable += 1
        if (
            r.get("control_ok")
            and r.get("wordpred_disagreements")
            and r.get("broken_periods_l2")
        ):
            excluded.append({
                "key": r.get("key"), "n": r.get("n"), "J": r.get("J"),
                "variant": r.get("variant"), "reducer": r.get("reducer"),
                "broken_periods_l2": r.get("broken_periods_l2"),
            })
    rate = (honest_usable / honest_total) if honest_total else None
    return {
        "honest_periods_measured": honest_total,
        "honest_word_usable": honest_usable,
        "honest_word_usable_rate": rate,
        "breaks_excluded_by_wordpred_only": excluded,
        "predictor_miscalibrated": rate is not None and rate < 0.9,
    }


def _summarize_periods(result: dict) -> list[dict]:
    """Keep the per-period numbers the plots need; drop the trace (far too
    big to checkpoint for every unit of an overnight grid)."""
    out = []
    for row in result.get("rows", []):
        out.append({
            "period": row.get("period"),
            "periods_back": row.get("periods_back"),
            "gs_norm": row.get("gs_norm"),
            "word_gs": row.get("word_gs"),
            "honest_word_gs": row.get("honest_word_gs"),
            "threshold": row.get("threshold"),
            "level1_norm_ok": row.get("level1_norm_ok"),
            "level2_search_break": row.get("level2_search_break"),
            "level3_plaintext_break": row.get("level3_plaintext_break"),
            "l2_matches_wordpred": row.get("l2_matches_wordpred"),
            "control_garbage_passed": row.get("control_garbage_passed"),
            "control_wrong_period_passed": row.get("control_wrong_period_passed"),
        })
    return out


def run_unit(n: int, J: int, variant: str, reducer: str, repeat: int, seed: int,
             config: SweepConfig, base_params: Params) -> dict:
    """One (cell, repeat). Never raises: a thrown cell is recorded as an
    error and the job continues (PATCH 08 §3)."""
    key = unit_key(n, J, variant, reducer, repeat, seed)
    started = time.time()
    base = {
        "key": key, "n": n, "J": J, "variant": variant, "reducer": reducer,
        "repeat": repeat, "seed": seed, "records_per_period": config.records_per_period,
    }
    try:
        result = end_to_end_experiment(
            J=J, base_params=base_params, n=n, seed=seed,
            h1_variant=variant, reducer_name=reducer,
            records_per_period=config.records_per_period,
        )
        record = {
            **base,
            "status": "ok",
            "control_ok": result.get("control_ok"),
            "control_passed_periods": result.get("control_passed_periods", []),
            "wrong_period_control_passed_periods": result.get("wrong_period_control_passed_periods", []),
            "wordpred_disagreements": result.get("wordpred_disagreements", []),
            "any_l2_break": result.get("any_l2_break"),
            "any_l3_break": result.get("any_l3_break"),
            "broken_periods_l2": result.get("broken_periods_l2", []),
            "broken_periods_l3": result.get("broken_periods_l3", []),
            "reducer_method": result.get("reducer_method"),
            "headline": result.get("headline"),
            "periods": _summarize_periods(result),
            "elapsed_s": time.time() - started,
            "error": None,
        }
        record["trusted"] = record_is_trusted(record)
        return record
    except Exception as e:  # noqa: BLE001 -- one bad cell must not kill the night
        return {
            **base,
            "status": "error",
            "trusted": False,
            "error": f"{type(e).__name__}: {e}",
            "traceback": traceback.format_exc(limit=8),
            "elapsed_s": time.time() - started,
            "periods": [],
        }


# --------------------------------------------------------------------------
# The background job
# --------------------------------------------------------------------------

class SweepJob:
    def __init__(self, job_id: str, config: SweepConfig, base_params: Params) -> None:
        self.job_id = job_id
        self.config = config
        self.base_params = base_params
        self._stop = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def request_stop(self) -> None:
        self._stop.set()

    def start(self) -> None:
        self.thread = threading.Thread(target=self._run, name=f"sweep-{self.job_id}", daemon=True)
        self.thread.start()

    def _run(self) -> None:
        if not acquire_job_lock(self.job_id):
            # Another live process already owns this job; running it here too
            # would append the same units twice.
            return
        try:
            self._run_locked()
        except Exception as e:  # noqa: BLE001 -- outside the per-unit guard; never leave "running" forever
            meta = load_meta(self.job_id) or {"job_id": self.job_id}
            meta["status"] = "failed"
            meta["stop_reason"] = f"job crashed outside a unit: {type(e).__name__}: {e}"
            write_meta(self.job_id, meta)
        finally:
            release_job_lock(self.job_id)

    def _run_locked(self) -> None:
        cfg = self.config
        units = list(cfg.units())
        total = len(units)

        # RESUME (PATCH 08 §3): anything already on disk for this job is
        # skipped, keyed by the idempotency key -- never double-counted.
        done_keys = {r.get("key") for r in load_records(self.job_id)}
        session_start = time.time()
        meta = load_meta(self.job_id) or {}
        prior_elapsed = float(meta.get("elapsed_s") or 0.0)
        _stop_path(self.job_id).unlink(missing_ok=True)
        meta.update({
            "job_id": self.job_id,
            "config": asdict(cfg),
            "total": total,
            "done": len(done_keys),
            "status": "running",
            "stop_reason": None,
            "started_at": meta.get("started_at", session_start),
            "resumed_at": session_start if done_keys else None,
            "q": self.base_params.q,
            "base_params": params_to_dict(self.base_params),
        })
        write_meta(self.job_id, meta)

        # max_hours bounds THIS session; a resumed job gets a fresh budget.
        deadline = session_start + cfg.max_hours * 3600.0
        for (n, J, variant, reducer, repeat, seed) in units:
            key = unit_key(n, J, variant, reducer, repeat, seed)
            if key in done_keys:
                continue
            if self._stop.is_set() or _stop_path(self.job_id).exists():
                meta["status"] = "stopped"
                meta["stop_reason"] = "stopped on request; checkpointed cleanly"
                write_meta(self.job_id, meta)
                return
            if time.time() > deadline:
                meta["status"] = "stopped"
                meta["stop_reason"] = f"max_hours ({cfg.max_hours}h) reached; checkpointed cleanly"
                write_meta(self.job_id, meta)
                return

            record = run_unit(n, J, variant, reducer, repeat, seed, cfg, self.base_params)
            append_record(self.job_id, record)
            done_keys.add(key)
            meta["done"] = len(done_keys)
            meta["elapsed_s"] = prior_elapsed + (time.time() - session_start)
            write_meta(self.job_id, meta)

        meta["status"] = "done"
        meta["finished_at"] = time.time()
        meta["elapsed_s"] = prior_elapsed + (time.time() - session_start)
        write_meta(self.job_id, meta)


def _stop_path(job_id: str) -> Path:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    return RESULTS_DIR / f"sweep_{job_id}.stop"


_JOBS: dict[str, SweepJob] = {}
_JOBS_LOCK = threading.Lock()


def start_job(config: SweepConfig, base_params: Params, job_id: Optional[str] = None) -> str:
    job_id = job_id or uuid.uuid4().hex[:12]
    job = SweepJob(job_id, config, base_params)
    with _JOBS_LOCK:
        _JOBS[job_id] = job
    job.start()
    return job_id


def stop_job(job_id: str) -> bool:
    """Request a clean stop. Works across processes: the runner checks a
    stop-file before every unit, so a stop sent to any server instance reaches
    whichever process actually owns the job."""
    meta = load_meta(job_id)
    if meta is None:
        return False
    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
    if job is not None:
        job.request_stop()
    if meta.get("status") == "running":
        _stop_path(job_id).write_text(str(time.time()))
        owner_alive = False
        lock = _lock_path(job_id)
        if lock.exists():
            try:
                owner_alive = _pid_alive(int(lock.read_text().strip()))
            except ValueError:
                owner_alive = False
        if not owner_alive and job is None:
            # Nobody is running it (e.g. the server died) -- settle the meta
            # so status stops claiming "running".
            meta["status"] = "stopped"
            meta["stop_reason"] = "stop requested; no live process was running this job"
            write_meta(job_id, meta)
        return True
    return job is not None


def resume_interrupted_jobs(base_params: Params) -> list[str]:
    """PATCH 08 §3: on server start, pick up any job whose meta still says
    "running" -- the previous process died mid-run. The lock skips jobs a
    different live process still owns, and resume itself skips every unit
    already on disk, so this is safe to call on every start (including each
    --reload)."""
    resumed = []
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    for meta_path in RESULTS_DIR.glob("sweep_*.meta.json"):
        try:
            meta = json.loads(meta_path.read_text())
        except json.JSONDecodeError:
            continue
        if meta.get("status") != "running":
            continue
        job_id = meta.get("job_id")
        lock = _lock_path(job_id)
        if lock.exists():
            try:
                pid = int(lock.read_text().strip())
            except ValueError:
                pid = -1
            if pid > 0 and pid != os.getpid() and _pid_alive(pid):
                continue
        with _JOBS_LOCK:
            if job_id in _JOBS:
                continue
        config = SweepConfig(**meta["config"])
        # Resume with the params the job STARTED with, not whatever the
        # caller defaults to -- otherwise one job's units would silently mix
        # two parameter sets.
        job_params = params_from_dict(meta["base_params"]) if meta.get("base_params") else base_params
        start_job(config, job_params, job_id=job_id)
        resumed.append(job_id)
    return resumed


def job_status(job_id: str) -> Optional[dict]:
    meta = load_meta(job_id)
    if meta is None:
        return None
    records = load_records(job_id)
    total = meta.get("total", 0)
    done = len(records)
    trusted = sum(1 for r in records if r.get("trusted"))
    errored = sum(1 for r in records if r.get("status") == "error")
    untrusted = done - trusted - errored
    elapsed = meta.get("elapsed_s", 0.0)
    rate = (elapsed / done) if done else 0.0
    return {
        "job_id": job_id,
        "status": meta.get("status"),
        "stop_reason": meta.get("stop_reason"),
        "done": done,
        "total": total,
        "trusted_units": trusted,
        "untrusted_units": untrusted,
        "error_units": errored,
        "elapsed_s": elapsed,
        "eta_s": rate * max(total - done, 0),
        "config": meta.get("config"),
        "started_at": meta.get("started_at"),
    }


# --------------------------------------------------------------------------
# Aggregation (PATCH 08 §5) + plots (§6) + conclusion (§7)
# --------------------------------------------------------------------------

def aggregate_cells(records: list[dict], config: SweepConfig, gate: str = "strict") -> list[dict]:
    """Collapse repeats into one outcome per cell.

    Order of checks matters and is deliberately conservative: a cell with no
    completed repeats is "skipped", never "survives" (PATCH 08 §8's
    test_skipped_never_survives), and a cell whose repeats mostly failed the
    guardrails is "untrusted" rather than being decided by the minority that
    passed.
    """
    by_cell: dict[tuple, list[dict]] = {}
    for r in records:
        by_cell.setdefault((r["n"], r["J"], r["variant"], r["reducer"]), []).append(r)

    cells = []
    for (n, J, variant, reducer) in config.cells():
        reps = by_cell.get((n, J, variant, reducer), [])
        trusted = [r for r in reps if record_is_trusted(r, gate)]
        errored = [r for r in reps if r.get("status") == "error"]
        broke = [r for r in trusted if r.get("broken_periods_l2")]
        break_rate = (len(broke) / len(trusted)) if trusted else None

        expected = config.repeats
        needed_for_trust = math.ceil(expected / 2)
        if not reps:
            outcome = "skipped"
        elif len(errored) == len(reps):
            outcome = "error"
        elif len(trusted) < needed_for_trust:
            outcome = "untrusted"
        elif break_rate and break_rate > 0:
            outcome = "break"
        else:
            outcome = "survives"

        broken_periods: set[int] = set()
        for r in broke:
            broken_periods.update(r.get("broken_periods_l2", []))

        cells.append({
            "n": n, "J": J, "variant": variant, "reducer": reducer,
            "outcome": outcome,
            "break_rate": break_rate,
            "repeats_done": len(reps),
            "repeats_expected": expected,
            "trusted_repeats": len(trusted),
            "broken_trusted_repeats": len(broke),
            "error_repeats": len(errored),
            "broken_periods_l2": sorted(broken_periods),
            "errors": sorted({r.get("error") for r in errored if r.get("error")}),
        })
    return cells


def _mean_std(xs: list[float]) -> tuple[Optional[float], Optional[float]]:
    vals = [x for x in xs if x is not None]
    if not vals:
        return (None, None)
    mean = sum(vals) / len(vals)
    if len(vals) < 2:
        return (mean, 0.0)
    var = sum((x - mean) ** 2 for x in vals) / (len(vals) - 1)
    return (mean, math.sqrt(var))


def plot_payloads(records: list[dict], cells: list[dict], config: SweepConfig, gate: str = "strict") -> dict:
    """Plot A-D data (PATCH 08 §6), computed from TRUSTED repeats only where
    the plot is making a claim about outcomes."""
    trusted = [r for r in records if record_is_trusted(r, gate)]

    # Plot A -- outcome heatmap, one panel per (variant, reducer).
    panels = []
    for variant in config.h1_variants:
        for reducer in config.reducers:
            panel_cells = [c for c in cells if c["variant"] == variant and c["reducer"] == reducer]
            panels.append({
                "variant": variant, "reducer": reducer,
                "n_values": sorted({c["n"] for c in panel_cells}),
                "J_values": sorted({c["J"] for c in panel_cells}),
                "cells": panel_cells,
            })
    plot_a = {"panels": panels}

    # Plot B -- word_gs (mean +- sd over trusted repeats) vs threshold, by
    # periods_back, one series per n. This is the mechanistic "why".
    plot_b = {}
    for variant in config.h1_variants:
        for reducer in config.reducers:
            series = []
            for n in sorted({r["n"] for r in trusted}):
                buckets: dict[int, list[float]] = {}
                thresholds: dict[int, list[float]] = {}
                for r in trusted:
                    if r["n"] != n or r["variant"] != variant or r["reducer"] != reducer:
                        continue
                    for p in r.get("periods", []):
                        pb = p.get("periods_back")
                        if pb is None:
                            continue
                        if p.get("word_gs") is not None:
                            buckets.setdefault(pb, []).append(p["word_gs"])
                        if p.get("threshold") is not None:
                            thresholds.setdefault(pb, []).append(p["threshold"])
                points = []
                for pb in sorted(buckets):
                    mean, sd = _mean_std(buckets[pb])
                    thr_mean, _ = _mean_std(thresholds.get(pb, []))
                    points.append({
                        "periods_back": pb, "word_gs_mean": mean, "word_gs_sd": sd,
                        "threshold": thr_mean, "samples": len(buckets[pb]),
                    })
                if points:
                    series.append({"n": n, "points": points})
            plot_b[f"{variant}|{reducer}"] = series

    # Plot C -- tooling sensitivity: break_rate vs n, per reducer.
    plot_c = []
    for n in sorted({c["n"] for c in cells}):
        row = {"n": n}
        for reducer in config.reducers:
            rel = [c for c in cells if c["n"] == n and c["reducer"] == reducer and c["break_rate"] is not None]
            row[reducer] = (sum(c["break_rate"] for c in rel) / len(rel)) if rel else None
        plot_c.append(row)

    # Plot D -- dimension trend: trusted cells broken vs surviving, per n.
    plot_d = []
    for n in sorted({c["n"] for c in cells}):
        rel = [c for c in cells if c["n"] == n]
        plot_d.append({
            "n": n,
            "broke": sum(1 for c in rel if c["outcome"] == "break"),
            "survives": sum(1 for c in rel if c["outcome"] == "survives"),
            "untrusted": sum(1 for c in rel if c["outcome"] == "untrusted"),
            "error": sum(1 for c in rel if c["outcome"] in ("error", "skipped")),
        })

    return {"plot_a": plot_a, "plot_b": plot_b, "plot_c": plot_c, "plot_d": plot_d}


def build_conclusion(
    cells: list[dict], config: SweepConfig, records: list[dict],
    gate: str = "strict", diagnostics: Optional[dict] = None,
) -> str:
    """PATCH 08 §7 -- a paragraph of MEASURED numbers, resting only on trusted
    cells, never claiming beyond the tested grid.

    It also refuses to present an artifact of the gate as a finding: under the
    strict gate, if genuine-looking breaks (negative controls held, same N0
    recovered) were excluded ONLY because the word-basis predictor disagreed,
    and that predictor is measurably miscalibrated on the honest doctor's own
    working bases, "consistent negative result" would be a claim the data do
    not support. The paragraph says so instead.
    """
    diagnostics = diagnostics if diagnostics is not None else gate_diagnostics(records)
    survives = [c for c in cells if c["outcome"] == "survives"]
    broke = [c for c in cells if c["outcome"] == "break"]
    untrusted = [c for c in cells if c["outcome"] == "untrusted"]
    errored = [c for c in cells if c["outcome"] in ("error", "skipped")]
    trusted_total = len(survives) + len(broke)

    gate_text = (
        "negative controls must fail AND the word-basis cross-check must agree"
        if gate == "strict" else
        "negative controls must fail (word-basis cross-check NOT required)"
    )
    head = (
        f"Batch sweep over n\u2208{sorted(set(config.n_values))}, J\u2208{sorted(set(config.J_values))}, "
        f"{config.h1_variants}, {config.reducers}, {config.repeats} repeats/cell, "
        f"records/period={config.records_per_period}; trust gate: {gate_text}. "
    )

    excluded = diagnostics["breaks_excluded_by_wordpred_only"] if gate == "strict" else []
    rate = diagnostics["honest_word_usable_rate"]
    gate_caveat = ""
    if excluded:
        cells_hit = sorted({(e["n"], e["J"]) for e in excluded})
        gate_caveat = (
            f"CAUTION: {len(excluded)} repeat(s) recovered the doctor's N0 with every negative "
            f"control holding, but were excluded ONLY because the word-basis predictor "
            f"disagreed (cells n,J = {cells_hit}). That predictor rated the honest doctor's own "
            f"word basis usable in only "
            + (f"{rate:.0%}" if rate is not None else "an unmeasured fraction")
            + " of frozen periods, although the honest search provably works at every one -- "
            f"so it rejects bases that demonstrably work, and this gate is biased toward "
            f"'no break'. Compare the controls-only view before reporting a negative result. "
        )

    if trusted_total == 0:
        return head + (
            f"NO cell produced enough trusted repeats to support a verdict "
            f"({len(untrusted)} untrusted, {len(errored)} errored/skipped). No conclusion "
            f"can be drawn from this run under this gate. "
        ) + gate_caveat

    body = (
        f"Of {trusted_total} trusted cells, {len(survives)} survive (the attack recovered no "
        f"past period's search capability) and {len(broke)} show a break (break_rate>0)"
    )
    if broke:
        detail = ", ".join(
            f"n={c['n']},J={c['J']} ({c['broken_trusted_repeats']}/{c['trusted_repeats']} repeats, "
            f"periods {c['broken_periods_l2']})"
            for c in sorted(broke, key=lambda c: (c["n"], c["J"]))
        )
        body += f", specifically at {detail}. "
        broken_ns = sorted({c["n"] for c in broke})
        clean_ns = sorted({c["n"] for c in survives if c["n"] not in broken_ns})
        if clean_ns:
            body += f"Breaks appear at n\u2208{broken_ns} and not at n\u2208{clean_ns} among trusted cells. "
        else:
            body += f"Breaks appear at every trusted dimension tested (n\u2208{broken_ns}). "
    elif excluded:
        body += (
            ". No break survived this gate, but that is NOT a clean negative result -- see the "
            "caution below. "
        )
    else:
        body += (
            ". No trusted configuration yielded a functional forward-security break -- a "
            "consistent negative result across the tested grid. "
        )

    tail = (
        f"{len(untrusted)} cells were untrusted and {len(errored)} errored or were skipped; "
        f"all of these are excluded from the counts above. "
        f"Demonstration parameters throughout -- cryptographic-parameter behaviour requires "
        f"large-n BKZ cost estimates this lab does not perform, and these results describe "
        f"only the tested grid, not all parameters. "
    )
    return head + body + tail + gate_caveat


def aggregate(job_id: str, gate: str = "strict") -> Optional[dict]:
    if gate not in GATES:
        raise ValueError(f"gate must be one of {GATES}")
    meta = load_meta(job_id)
    if meta is None:
        return None
    config = SweepConfig(**meta["config"])
    records = load_records(job_id)
    cells = aggregate_cells(records, config, gate)
    diagnostics = gate_diagnostics(records)
    return {
        "job_id": job_id,
        "status": meta.get("status"),
        "gate": gate,
        "config": asdict(config),
        "cells": cells,
        "plots": plot_payloads(records, cells, config, gate),
        "conclusion": build_conclusion(cells, config, records, gate, diagnostics),
        "gate_diagnostics": diagnostics,
        "counts": {
            "cells_total": len(cells),
            "survives": sum(1 for c in cells if c["outcome"] == "survives"),
            "break": sum(1 for c in cells if c["outcome"] == "break"),
            "untrusted": sum(1 for c in cells if c["outcome"] == "untrusted"),
            "error": sum(1 for c in cells if c["outcome"] == "error"),
            "skipped": sum(1 for c in cells if c["outcome"] == "skipped"),
            "units_done": len(records),
            "units_trusted": sum(1 for r in records if record_is_trusted(r, gate)),
        },
    }


def records_csv(job_id: str) -> str:
    """Flat per-period CSV — the underlying numbers for the writeup."""
    records = load_records(job_id)
    cols = [
        "key", "n", "J", "variant", "reducer", "repeat", "seed", "status", "trusted",
        "control_ok", "any_l2_break", "period", "periods_back", "gs_norm", "word_gs",
        "honest_word_gs", "threshold", "level1_norm_ok", "level2_search_break",
        "level3_plaintext_break", "l2_matches_wordpred", "control_garbage_passed",
        "control_wrong_period_passed", "error",
    ]
    lines = [",".join(cols)]

    def cell(v) -> str:
        if v is None:
            return ""
        if isinstance(v, bool):
            return "true" if v else "false"
        s = str(v)
        return f'"{s}"' if ("," in s or '"' in s) else s

    for r in records:
        periods = r.get("periods") or [{}]
        for p in periods:
            row = {**{k: r.get(k) for k in cols}, **{k: p.get(k) for k in p}}
            lines.append(",".join(cell(row.get(c)) for c in cols))
    return "\n".join(lines) + "\n"
