"""FastAPI surface for the PPSEB Analysis Lab (CLAUDE.md §5).

Single-user, in-memory session state — this is a demo/analysis instrument,
not a multi-tenant service. Every endpoint returns `{result, trace, params}`
so the frontend can render the step-by-step timeline alongside the outcome.
"""

from __future__ import annotations

import random
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
    forward_sec_experiment, scaling_sweep, H1_VARIANTS, DEFAULT_SWEEP_N_VALUES,
    DEFAULT_SWEEP_TIME_BUDGET_S,
)
from attacks.spec_defect import run_paper_version, run_corrected_version

app = FastAPI(title="PPSEB Analysis Lab API")

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


@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    from fastapi.responses import JSONResponse
    return JSONResponse(
        status_code=500,
        content={"error": str(exc), "traceback": traceback.format_exc()},
    )
