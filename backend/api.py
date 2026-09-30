"""FastAPI surface for the PPSEB Analysis Lab (CLAUDE.md §5).

Single-user, in-memory session state — this is a demo/analysis instrument,
not a multi-tenant service. Every endpoint returns `{result, trace, params}`
so the frontend can render the step-by-step timeline alongside the outcome.
"""

from __future__ import annotations

import json
import random
from contextlib import asynccontextmanager
import time
import traceback
from typing import Optional

import numpy as np
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ppseb.params import Params, default_params
from ppseb.scheme import (
    initialization, keyext, peks_encrypt, trapdoor, verify,
    encrypt_record, decrypt_record,
)
from ppseb.trace import Trace, jsonable
from attacks.kga import kga_attack
from attacks.forward_sec import (
    forward_sec_experiment, scaling_sweep, three_way_reduction_sweep, H1_VARIANTS,
    DEFAULT_SWEEP_N_VALUES, DEFAULT_SWEEP_TIME_BUDGET_S,
    DEFAULT_THREE_WAY_N_VALUES, DEFAULT_THREE_WAY_TIME_BUDGET_S,
)
from attacks.end_to_end import end_to_end_experiment, end_to_end_multi_n, DEFAULT_END_TO_END_N_VALUES
from attacks.spec_defect import run_paper_version, run_corrected_version
import sweep
from attacks import nq_sweep
from attacks import boundary
from attacks import recovery
import network as network_sim
from attacks import security_estimate
from attacks import pk_demo

# MUST happen here, at import time, on the MAIN thread: fpylll's cysignals
# dependency installs signal handlers on import and raises
# "signal only works in main thread" if a worker thread imports it first.
# The batch sweep (sweep.py) runs BKZ on a background thread, so without
# this warm-up every BKZ cell of an overnight job would die. Importing here
# leaves the module cached in sys.modules for the worker.
FPYLLL_READY = sweep.warm_up_native_libs()

@asynccontextmanager
async def lifespan(_app):
    """PATCH 08 §3: a job whose meta still says "running" belonged to a process
    that died (crash, restart, --reload). Resume it; the per-job lock skips any
    job another live process still owns, and resume skips units already on disk."""
    sweep.resume_interrupted_jobs(default_params())
    yield


app = FastAPI(title="PPSEB Analysis Lab API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # local analysis tool, not internet-facing
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------------------------------
# Session state
# --------------------------------------------------------------------------

class Session:
    def __init__(self) -> None:
        self.params: Params = default_params()
        self.pk: dict[int, np.ndarray] = {}
        self.sk: dict[int, np.ndarray] = {}
        self.mu: Optional[np.ndarray] = None
        self.u_pke: Optional[np.ndarray] = None
        self.seed_counter: int = 0

    def next_seed(self) -> int:
        self.seed_counter += 1
        return self.seed_counter

    def rngs(self) -> tuple[np.random.Generator, random.Random]:
        s = self.next_seed()
        return np.random.default_rng(s), random.Random(s)

    def max_period(self) -> int:
        return max(self.pk.keys()) if self.pk else -1

    def require_period(self, j: int) -> None:
        if j not in self.pk:
            raise HTTPException(400, f"period {j} does not exist yet; call /api/keyext first")


SESSION = Session()


def envelope(result: dict, trace: Trace | list[dict], params: Params) -> dict:
    trace_list = trace.to_list() if isinstance(trace, Trace) else trace
    return {
        "result": jsonable(result),
        "trace": jsonable(trace_list),
        "params": {
            "n": params.n, "q": params.q, "m": params.m,
            "sigma": params.sigma, "l": params.l,
        },
    }


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------

class InitRequest(BaseModel):
    n: int = 4
    q: int = 257
    sigma: float = 4.0
    l: int = 10
    m: int = 0  # 0 => derive


class KeyExtRequest(BaseModel):
    periods: int = Field(..., ge=0, description="Extend the chain up to (and including) this period")


class EncryptSearchRequest(BaseModel):
    record: str
    keyword: str
    query_keyword: str
    period: Optional[int] = None


class KgaRequest(BaseModel):
    secret_keyword: str
    dictionary: list[str]
    period: Optional[int] = None


class ForwardRequest(BaseModel):
    J: int = Field(..., ge=1, le=12)
    h1_variant: str = "low_norm"
    seed: int = 0


class ForwardSweepRequest(BaseModel):
    J: int = Field(3, ge=2, le=6)
    n_values: list[int] = Field(default_factory=lambda: list(DEFAULT_SWEEP_N_VALUES))
    seed: int = 0
    time_budget_s: float = Field(DEFAULT_SWEEP_TIME_BUDGET_S, gt=0, le=600)


class ForwardFairnessRequest(BaseModel):
    J: int = Field(2, ge=2, le=4)
    n_values: list[int] = Field(default_factory=lambda: list(DEFAULT_THREE_WAY_N_VALUES))
    seed: int = 0
    time_budget_s: float = Field(DEFAULT_THREE_WAY_TIME_BUDGET_S, gt=0, le=900)


class ForwardE2ERequest(BaseModel):
    J: int = Field(2, ge=2, le=4)
    n: int = 4
    seed: int = 0
    reducer_name: str = "bkz"


class ForwardE2EMultiRequest(BaseModel):
    J: int = Field(2, ge=2, le=4)
    n_values: list[int] = Field(default_factory=lambda: list(DEFAULT_END_TO_END_N_VALUES))
    seed: int = 0
    reducer_name: str = "bkz"


class SpecRequest(BaseModel):
    periods: int = Field(3, ge=1, le=12)
    seed: int = 0


# --------------------------------------------------------------------------
# Endpoints
# --------------------------------------------------------------------------

@app.get("/api/health")
def health():
    return {"status": "ok", "time": time.time()}


@app.post("/api/init")
def init(req: InitRequest):
    params = Params(n=req.n, q=req.q, sigma=req.sigma, l=req.l, m=req.m)
    problems = params.validate()
    if problems:
        raise HTTPException(422, {"problems": problems})

    trace = Trace()
    rng = np.random.default_rng(int(time.time() * 1000) % (2**31))
    state = initialization(params, rng, trace)

    SESSION.__init__()  # fresh session
    SESSION.params = params
    SESSION.pk[0] = state["pk_r0"]
    SESSION.sk[0] = state["sk_r0"]
    SESSION.mu = state["mu"]
    SESSION.u_pke = state["u_pke"]

    result = {
        "shape_table": params.shape_table(),
        "pk_r0_preview": state["pk_r0"][:4, :12].tolist(),
        "max_period": 0,
    }
    return envelope(result, trace, params)


def _ensure_initialized():
    if not SESSION.pk:
        raise HTTPException(400, "call /api/init first")


@app.post("/api/keyext")
def api_keyext(req: KeyExtRequest):
    _ensure_initialized()
    params = SESSION.params
    trace = Trace()
    start = SESSION.max_period()
    if req.periods <= start:
        return envelope(
            {"chain": _chain_summary(0, start), "max_period": start},
            trace, params,
        )
    pk, sk = SESSION.pk[start], SESSION.sk[start]
    _rng, pyrng = SESSION.rngs()
    for j in range(start + 1, req.periods + 1):
        pk, sk = keyext(j, pk, sk, params, pyrng, trace)
        SESSION.pk[j] = pk
        SESSION.sk[j] = sk

    return envelope(
        {"chain": _chain_summary(0, req.periods), "max_period": req.periods},
        trace, params,
    )


def _chain_summary(lo: int, hi: int) -> list[dict]:
    from ppseb.linalg import gram_schmidt_norm
    out = []
    for j in range(lo, hi + 1):
        if j in SESSION.pk:
            out.append({
                "period": j,
                "pk_preview": SESSION.pk[j][:4, :12].tolist(),
                "sk_gram_schmidt_norm": gram_schmidt_norm(SESSION.sk[j]),
            })
    return out


@app.post("/api/encrypt-search")
def api_encrypt_search(req: EncryptSearchRequest):
    _ensure_initialized()
    params = SESSION.params
    j = req.period if req.period is not None else SESSION.max_period()
    SESSION.require_period(j)
    pk, sk, mu, u_pke = SESSION.pk[j], SESSION.sk[j], SESSION.mu, SESSION.u_pke

    trace = Trace()
    rng, pyrng = SESSION.rngs()

    ct = peks_encrypt(pk, req.keyword, j, mu, params, rng, pyrng, trace)
    trap = trapdoor(pk, sk, req.query_keyword, j, mu, params, pyrng, trace)
    match, y = verify(ct["CT1"], ct["CT2"], trap, params, trace)

    record_bytes = req.record.encode("utf-8")
    enc = encrypt_record(pk, record_bytes, u_pke, params, rng, pyrng, trace)
    decrypted = None
    if match:
        decrypted_bytes = decrypt_record(pk, sk, enc, u_pke, params, pyrng, trace)
        try:
            decrypted = decrypted_bytes.decode("utf-8")
        except UnicodeDecodeError:
            decrypted = None

    result = {
        "period": j,
        "match": match,
        "y_preview": y[:12].tolist(),
        "decrypted_record": decrypted if match else None,
        "encrypted_keyword": req.keyword,
        "query_keyword": req.query_keyword,
    }
    return envelope(result, trace, params)


@app.post("/api/attack/kga")
def api_attack_kga(req: KgaRequest):
    _ensure_initialized()
    params = SESSION.params
    j = req.period if req.period is not None else SESSION.max_period()
    SESSION.require_period(j)
    pk, sk, mu = SESSION.pk[j], SESSION.sk[j], SESSION.mu

    trace = Trace()
    _rng, pyrng = SESSION.rngs()
    trace.compute(
        "Doctor makes a trapdoor for the secret keyword",
        detail="This models the ONLY step that needs a secret: the doctor's sk_rj.",
        algo="KGA",
    )
    trap = trapdoor(pk, sk, req.secret_keyword, j, mu, params, pyrng, trace)

    attack_result = kga_attack(pk, mu, j, trap, req.dictionary, params, seed=SESSION.next_seed())
    combined_trace = trace.to_list() + attack_result["trace"]

    result = {
        "period": j,
        "secret_keyword": req.secret_keyword,
        "recovered_keyword": attack_result["recovered_keyword"],
        "guesses": attack_result["guesses"],
        "guesses_tried": attack_result["guesses_tried"],
        "success": attack_result["recovered_keyword"] == req.secret_keyword,
    }
    return envelope(result, combined_trace, params)


@app.post("/api/attack/forward")
def api_attack_forward(req: ForwardRequest):
    _ensure_initialized()
    if req.h1_variant not in H1_VARIANTS:
        raise HTTPException(422, f"h1_variant must be one of {H1_VARIANTS}")
    params = SESSION.params
    result = forward_sec_experiment(req.J, params, seed=req.seed, h1_variant=req.h1_variant)
    return envelope(
        {k: v for k, v in result.items() if k != "trace"},
        result["trace"], params,
    )


@app.post("/api/attack/forward-sweep")
async def api_attack_forward_sweep(req: ForwardSweepRequest):
    """PATCH 02 Task B — does the low_norm LLL break survive as n grows?
    Slower than the single-n experiment (each n rebuilds a fresh chain at
    its own m); bounded by an explicit wall-clock budget rather than
    hanging (see forward_sec.scaling_sweep's module docstring).

    Deliberately `async def` calling scaling_sweep directly (not via
    FastAPI's sync-endpoint threadpool): PATCH 03 Lever 2's optional fpylll
    BKZ path depends on cysignals, which can only install its signal
    handler on the MAIN thread — a plain `def` endpoint runs in a worker
    thread and raises "signal only works in main thread of the main
    interpreter". Running synchronously on the event loop thread blocks it
    for the sweep's duration, an acceptable trade-off for this single-user
    local lab (same "session, not a service" model as the rest of the app)
    given this is an explicitly slow, deliberately-clicked action.
    """
    _ensure_initialized()
    params = SESSION.params
    result = scaling_sweep(
        req.J, params, n_values=tuple(req.n_values), seed=req.seed,
        time_budget_s=req.time_budget_s,
    )
    return envelope(result, [], params)


@app.post("/api/attack/forward-fairness")
async def api_attack_forward_fairness(req: ForwardFairnessRequest):
    """PATCH 04 — closes the "defender got BKZ, attacker only got LLL"
    asymmetry left by PATCH 03: runs LLL_vs_LLL, BKZ_defender_only, and
    BKZ_vs_BKZ at each n, the last being the authoritative fairness test.
    `async def` for the same cysignals/main-thread reason as the sweep
    endpoint above. Slower still (two full chain builds per n) — n defaults
    to a smaller {4, 6} range; see three_way_reduction_sweep's docstring.
    """
    _ensure_initialized()
    params = SESSION.params
    result = three_way_reduction_sweep(
        req.J, params, n_values=tuple(req.n_values), seed=req.seed,
        time_budget_s=req.time_budget_s,
    )
    return envelope(result, [], params)


@app.post("/api/attack/forward-e2e")
async def api_attack_forward_e2e(req: ForwardE2ERequest):
    """PATCH 05 — end-to-end forward-security attack: builds and FREEZES
    the honest doctor's searchable database at each period, evolves the key
    to period J (stolen), then has the attacker reconstruct SK*_r|i and run
    the SAME search/decrypt code path against the frozen ciphertexts. Never
    a norm proxy — Level 2/3 are measured N0/plaintext equality. `async def`
    for the same cysignals/main-thread reason as the other slow endpoints.
    """
    _ensure_initialized()
    params = SESSION.params
    result = end_to_end_experiment(
        req.J, params, n=req.n, seed=req.seed, reducer_name=req.reducer_name,
    )
    return envelope(
        {k: v for k, v in result.items() if k != "trace"},
        result["trace"], params,
    )


@app.post("/api/attack/forward-e2e-multi")
async def api_attack_forward_e2e_multi(req: ForwardE2EMultiRequest):
    """Runs the end-to-end attack at multiple n (default {4, 8} — n=6 has
    no valid H2 for q=257, see attacks.end_to_end's module docstring) and
    reports the honest cross-dimension headline. Slower (one full run per
    n); each n's own trace stays nested in `per_n`, not hoisted to the top.
    """
    _ensure_initialized()
    params = SESSION.params
    result = end_to_end_multi_n(
        req.J, params, n_values=tuple(req.n_values), seed=req.seed, reducer_name=req.reducer_name,
    )
    combined_trace = [ev for r in result["per_n"] if "error" not in r for ev in r.get("trace", [])]
    result_no_trace = {
        **result,
        "per_n": [{k: v for k, v in r.items() if k != "trace"} for r in result["per_n"]],
    }
    return envelope(result_no_trace, combined_trace, params)


@app.post("/api/attack/spec")
def api_attack_spec(req: SpecRequest):
    _ensure_initialized()
    params = SESSION.params
    pk0, sk0 = SESSION.pk[0], SESSION.sk[0]

    paper = run_paper_version(1, pk0, sk0, params)
    corrected = run_corrected_version(req.periods, params, seed=req.seed)

    combined_trace = paper["trace"] + corrected["trace"]
    result = {
        "paper": {"success": paper["success"], "failures": paper["failures"]},
        "corrected": {"success": corrected["success"], "chain": corrected["chain"]},
    }
    return envelope(result, combined_trace, params)


# --------------------------------------------------------------------------
# PATCH 08 — batch sweep (overnight grid, checkpointed, aggregated)
# --------------------------------------------------------------------------

class SweepStartRequest(BaseModel):
    n_values: list[int] = Field(default_factory=lambda: [4, 8])
    J_values: list[int] = Field(default_factory=lambda: [3, 4, 5, 6, 8])
    h1_variants: list[str] = Field(default_factory=lambda: ["low_norm"])
    reducers: list[str] = Field(default_factory=lambda: ["bkz"])
    records_per_period: int = Field(sweep.RECORDS_PER_PERIOD, ge=1, le=51)
    repeats: int = Field(3, ge=1, le=20)
    seed_base: int = 1000
    max_hours: float = Field(12.0, gt=0, le=72)

    def to_config(self) -> sweep.SweepConfig:
        return sweep.SweepConfig(
            n_values=self.n_values, J_values=self.J_values,
            h1_variants=self.h1_variants, reducers=self.reducers,
            records_per_period=self.records_per_period, repeats=self.repeats,
            seed_base=self.seed_base, max_hours=self.max_hours,
        )


@app.post("/api/sweep/preflight")
async def api_sweep_preflight(req: SweepStartRequest):
    """What this grid costs and which cells are already doomed, BEFORE a
    night is spent on it (see sweep.py's module docstring on the H2
    dimension constraint)."""
    return {"result": sweep.preflight(req.to_config(), SESSION.params.q)}


@app.post("/api/sweep/start")
async def api_sweep_start(req: SweepStartRequest):
    config = req.to_config()
    pre = sweep.preflight(config, SESSION.params.q)
    job_id = sweep.start_job(config, SESSION.params)
    return {"result": {"job_id": job_id, **pre}}


@app.get("/api/sweep/status")
async def api_sweep_status(job_id: str):
    status = sweep.job_status(job_id)
    if status is None:
        raise HTTPException(404, f"no such sweep job: {job_id}")
    return {"result": status}


@app.get("/api/sweep/results")
async def api_sweep_results(job_id: str, gate: str = "strict"):
    if gate not in sweep.GATES:
        raise HTTPException(400, f"gate must be one of {sweep.GATES}")
    agg = sweep.aggregate(job_id, gate)
    if agg is None:
        raise HTTPException(404, f"no such sweep job: {job_id}")
    return {"result": agg}


@app.post("/api/sweep/stop")
async def api_sweep_stop(job_id: str):
    ok = sweep.stop_job(job_id)
    if not ok:
        raise HTTPException(404, f"no running sweep job: {job_id}")
    return {"result": {"job_id": job_id, "stopping": True}}


@app.get("/api/sweep/jobs")
async def api_sweep_jobs():
    return {"result": sweep.list_jobs()}


@app.get("/api/sweep/export")
async def api_sweep_export(job_id: str, fmt: str = "csv"):
    from fastapi.responses import PlainTextResponse
    if sweep.load_meta(job_id) is None:
        raise HTTPException(404, f"no such sweep job: {job_id}")
    if fmt == "csv":
        return PlainTextResponse(sweep.records_csv(job_id), media_type="text/csv")
    if fmt == "jsonl":
        body = "\n".join(json.dumps(r) for r in sweep.load_records(job_id))
        return PlainTextResponse(body, media_type="application/x-ndjson")
    raise HTTPException(400, "fmt must be 'csv' or 'jsonl'")


# --------------------------------------------------------------------------
# PATCH 13 — (n, q) sweep: correctness-gated, public-key-only vs stolen-key
# --------------------------------------------------------------------------

class NqSweepRequest(BaseModel):
    n_values: list[int] = Field(default_factory=lambda: list(nq_sweep.DEFAULT_N_VALUES))
    q_values: list[int] = Field(default_factory=lambda: list(nq_sweep.DEFAULT_Q_VALUES))
    J: int = Field(nq_sweep.DEFAULT_J, ge=2, le=8)
    repeats: int = Field(nq_sweep.DEFAULT_REPEATS, ge=1, le=10)
    records_per_period: int = Field(nq_sweep.DEFAULT_RECORDS_PER_PERIOD, ge=2, le=51)
    seed_base: int = 1300
    cell_timeout_s: float = Field(nq_sweep.DEFAULT_CELL_TIMEOUT_S, gt=0, le=6 * 3600)


@app.post("/api/nq-sweep/start")
async def api_nq_sweep_start(req: NqSweepRequest):
    job_id = nq_sweep.start_job(
        n_values=req.n_values, q_values=req.q_values, J=req.J, repeats=req.repeats,
        records_per_period=req.records_per_period, seed_base=req.seed_base, timeout_s=req.cell_timeout_s,
    )
    return {"result": {"job_id": job_id}}


@app.get("/api/nq-sweep/status")
async def api_nq_sweep_status(job_id: str):
    snap = nq_sweep.job_snapshot(job_id)
    if snap is None:
        raise HTTPException(404, f"no such (n, q) sweep job: {job_id}")
    return {"result": snap}


@app.get("/api/nq-sweep/jobs")
async def api_nq_sweep_jobs():
    return {"result": nq_sweep.list_jobs()}


# --------------------------------------------------------------------------
# PATCH 14/15 — security boundary: public-key-only AND stolen-key attacks
# on the same estimated-bits axis
# --------------------------------------------------------------------------

class BoundaryRequest(BaseModel):
    grid: list[list[int]] = Field(default_factory=lambda: [list(c) for c in boundary.DEFAULT_GRID])
    J: int = Field(boundary.DEFAULT_J, ge=2, le=6)
    records_per_period: int = Field(boundary.DEFAULT_RECORDS_PER_PERIOD, ge=2, le=51)
    seed: int = 1400
    beta_ladder: list[int] = Field(default_factory=lambda: list(boundary.DEFAULT_BETA_LADDER))
    attack_budget_s: float = Field(boundary.DEFAULT_ATTACK_BUDGET_S, gt=0, le=3 * 3600)
    cell_timeout_s: float = Field(boundary.DEFAULT_CELL_TIMEOUT_S, gt=0, le=6 * 3600)
    max_hours: float = Field(boundary.DEFAULT_MAX_HOURS, gt=0, le=48)
    run_stolen: bool = True
    # PATCH 15: resuming an existing job skips every unit already in its JSONL.
    job_id: Optional[str] = None


@app.post("/api/boundary/start")
async def api_boundary_start(req: BoundaryRequest):
    job_id = boundary.start_job(
        grid=[tuple(c) for c in req.grid], J=req.J, records_per_period=req.records_per_period,
        seed=req.seed, beta_ladder=tuple(req.beta_ladder), attack_budget_s=req.attack_budget_s,
        timeout_s=req.cell_timeout_s, max_hours=req.max_hours, run_stolen=req.run_stolen,
        job_id=req.job_id,
    )
    return {"result": {"job_id": job_id}}


@app.get("/api/boundary/status")
async def api_boundary_status(job_id: str):
    snap = boundary.job_snapshot(job_id)
    if snap is None:
        raise HTTPException(404, f"no such boundary job: {job_id}")
    return {"result": snap}


@app.get("/api/boundary/jobs")
async def api_boundary_jobs():
    return {"result": boundary.list_jobs()}


@app.get("/api/boundary/estimate")
async def api_boundary_estimate(n: int, q: int, target_norm: float, sigma: float = 4.0):
    from ppseb.params import derived_m
    return {"result": security_estimate.estimate_bits(n, q, derived_m(n, q), target_norm, sigma)}


# --------------------------------------------------------------------------
# PATCH 16 — public-key-only break demo
# --------------------------------------------------------------------------

class PkDemoRequest(BaseModel):
    n: int = Field(pk_demo.DEFAULT_N, ge=2, le=16)
    q: int = Field(pk_demo.DEFAULT_Q, ge=17)
    seed: int = 1600
    records: int = Field(pk_demo.DEFAULT_RECORDS, ge=2, le=10)
    beta: int = Field(pk_demo.DEMO_BETA, ge=2, le=40)
    dictionary: list[str] = Field(default_factory=lambda: list(pk_demo.DISEASE_DICTIONARY))


@app.post("/api/pk-demo/run")
async def api_pk_demo_run(req: PkDemoRequest):
    """`async def` for the same cysignals/main-thread reason as the other
    BKZ-using endpoints. Takes ~35s at the default parameters."""
    if len(req.dictionary) < 2:
        raise HTTPException(400, "the dictionary needs at least two diseases")
    result = pk_demo.run_public_key_demo(
        n=req.n, q=req.q, seed=req.seed, records=req.records,
        dictionary=tuple(req.dictionary), beta=req.beta,
    )
    params = Params(n=req.n, q=req.q, sigma=SESSION.params.sigma, l=SESSION.params.l, m=0)
    return envelope({k: v for k, v in result.items() if k != "trace"}, result["trace"], params)


# --------------------------------------------------------------------------
# PATCH 18 — the Network tab: doctor / cloud / verifier / attacker simulation
# --------------------------------------------------------------------------

class NetworkNewRequest(BaseModel):
    n: int = Field(network_sim.PAPER_DEFAULT[0], ge=2, le=16)
    q: int = Field(network_sim.PAPER_DEFAULT[1], ge=17)
    seed: int = 18


class NetworkRecordRequest(BaseModel):
    session_id: str
    keyword: str
    text: str = Field(min_length=1, max_length=200)


class NetworkKeywordRequest(BaseModel):
    session_id: str
    keyword: str


class NetworkSessionRequest(BaseModel):
    session_id: str


class NetworkDecryptRequest(BaseModel):
    session_id: str
    record_id: int


class NetworkAttackRequest(BaseModel):
    session_id: str
    kind: str = "public_key"
    periods: list[int]
    stolen_period: Optional[int] = None
    control: bool = False
    beta: int = Field(network_sim.DEMO_BETA, ge=2, le=40)
    budget_s: float = Field(network_sim.DEFAULT_ATTACK_BUDGET_S, gt=0, le=1800)


def _network(session_id: str) -> "network_sim.NetworkSession":
    try:
        return network_sim.get_session(session_id)
    except KeyError as e:
        raise HTTPException(404, str(e))


def _network_envelope(session, result: dict, trace=None) -> dict:
    """Every network call returns the new state alongside its own result, so
    the canvas never has to guess what changed."""
    return envelope({**result, "state": session.state()}, trace or [], session.params)


@app.get("/api/network/options")
async def api_network_options():
    return {"result": network_sim.parameter_options()}


@app.post("/api/network/new")
async def api_network_new(req: NetworkNewRequest):
    """A rebuild at new (n, q). An (n, q) that fails H2 or the correctness gate
    comes back `available: false` with the reason, rather than a broken demo."""
    session = network_sim.new_session(n=req.n, q=req.q, seed=req.seed)
    return _network_envelope(session, {"created": True})


@app.get("/api/network/state")
async def api_network_state(session_id: str):
    return _network_envelope(_network(session_id), {})


@app.post("/api/network/record")
async def api_network_record(req: NetworkRecordRequest):
    session = _network(req.session_id)
    try:
        event = session.add_record(req.keyword, req.text)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(400, str(e))
    return _network_envelope(session, {"event": event})


@app.post("/api/network/search")
async def api_network_search(req: NetworkKeywordRequest):
    session = _network(req.session_id)
    try:
        event = session.search(req.keyword)
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return _network_envelope(session, {"event": event})


@app.post("/api/network/advance")
async def api_network_advance(req: NetworkSessionRequest):
    session = _network(req.session_id)
    try:
        event = session.advance_period()
    except RuntimeError as e:
        raise HTTPException(400, str(e))
    return _network_envelope(session, {"event": event})


@app.post("/api/network/decrypt")
async def api_network_decrypt(req: NetworkDecryptRequest):
    session = _network(req.session_id)
    try:
        event = session.doctor_decrypt(req.record_id)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(400, str(e))
    return _network_envelope(session, {"event": event})


@app.post("/api/network/attack")
async def api_network_attack(req: NetworkAttackRequest):
    """`async def` for the same cysignals/main-thread reason as the other
    BKZ-using endpoints."""
    session = _network(req.session_id)
    try:
        result = session.attack(req.kind, req.periods, stolen_period=req.stolen_period,
                                control=req.control, beta=req.beta, budget_s=req.budget_s)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(400, str(e))
    return _network_envelope(session, {k: v for k, v in result.items() if k != "trace"},
                             result["trace"])



# --------------------------------------------------------------------------
# PATCH 19 — recovery analysis: what actually decides break vs no-break
# --------------------------------------------------------------------------

class RecoveryRequest(BaseModel):
    n: int = Field(4, ge=2, le=16)
    q: int = Field(257, ge=17)
    J: int = Field(recovery.DEFAULT_J, ge=1, le=4)
    records_per_period: int = Field(recovery.RECORDS_PER_PERIOD, ge=2, le=60)
    samples: int = Field(recovery.SAMPLES, ge=2, le=400)
    repeats: int = Field(recovery.REPEATS, ge=1, le=10)
    seed: int = recovery.DEFAULT_SEED
    beta: int = Field(recovery.DEMO_BETA, ge=2, le=40)
    sigma_scales: list[float] = Field(default_factory=lambda: list(recovery.SIGMA_SCALES))


@app.post("/api/recovery/start")
async def api_recovery_start(req: RecoveryRequest):
    """A full-size run is thousands of SamplePre draws, so it runs as a job the
    UI polls rather than a request that hangs."""
    job_id = recovery.start_job(
        n=req.n, q=req.q, J=req.J, records_per_period=req.records_per_period,
        samples=req.samples, repeats=req.repeats, seed=req.seed, beta=req.beta,
        sigma_scales=tuple(req.sigma_scales),
    )
    return {"result": {"job_id": job_id}}


@app.get("/api/recovery/status")
async def api_recovery_status(job_id: str):
    snap = recovery.job_snapshot(job_id)
    if snap is None:
        raise HTTPException(404, f"no such recovery job: {job_id}")
    return {"result": snap}


@app.get("/api/recovery/jobs")
async def api_recovery_jobs():
    return {"result": recovery.list_jobs()}



@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "traceback": traceback.format_exc()},
    )
