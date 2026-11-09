"""FastAPI surface for MedVault-PQ core (M1-M4), mounted beside the PPSEB lab.

Same conventions as the existing `api.py`: a single-user in-memory session, and
every response is `{result, trace, params}` so the frontend renders one timeline
component for every operation.

Mounted by adding two lines to `api.py`; nothing in the existing surface changes.
The PPSEB research tabs keep working exactly as before — the lab is the baseline
and the attack target, not a thing this router replaces.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .config import MedVaultConfig, library_versions
from .consent import ConsentError
from . import demo as demo_module
from .demo import FIGURES, collect_traces, load_report, record_run, run_demo
from .envelope import Scope
from .harness import (ATTACKER_MODELS, run_access_pattern, run_kga, run_plant, run_replay,
                      run_retrieval_replay)
from .key_tree import KeyTree, KeyTreeConfig
from .repro import run_repro
from .service import DemoWorld, build_world
from .zk import CIRCUITS, ZKAuthorisation

router = APIRouter(prefix="/api/medvault", tags=["medvault"])

#: Single-user local tool, same session model as `api.py`.
SESSION: dict[str, DemoWorld | None] = {"world": None, "tree": None}


def _world() -> DemoWorld:
    world = SESSION["world"]
    if world is None:
        # The interactive surface proves when the circuit is built, and the
        # response says which mode actually ran.
        SESSION["world"] = world = build_world(MedVaultConfig(zk_mode="auto"))
    return world


def _envelope(result: dict, trace, world: DemoWorld) -> dict:
    params = world.params
    return {
        "result": result,
        "trace": trace if isinstance(trace, list) else list(trace),
        "params": {
            "n": params.n, "q": params.q, "m": params.m,
            "sigma": params.sigma, "l": params.l,
        },
    }


# --------------------------------------------------------------------------
# Request models
# --------------------------------------------------------------------------

class SessionRequest(BaseModel):
    seed: int = 42
    mode: Literal["A", "B"] = "B"
    zk_mode: Literal["auto", "groth16", "signed"] = "auto"
    ledger_mode: Literal["memory", "hardhat"] = "memory"


class TreeRequest(BaseModel):
    depth: int = Field(default=4, ge=1, le=5)
    epoch: int = Field(default=0, ge=0)
    measure_peks: bool = True


class UploadRequest(BaseModel):
    record_id: str = Field(min_length=1, max_length=64)
    text: str = Field(min_length=1, max_length=8192)
    keywords: list[str] = Field(default_factory=list, max_length=16)
    tag: Optional[str] = None


class ScopePayload(BaseModel):
    kind: Literal["record_set", "record_tag"] = "record_tag"
    record_ids: list[str] = Field(default_factory=list)
    tag: str = ""


class GrantRequest(BaseModel):
    doctor_id: str
    scope: ScopePayload
    expiry_seconds: int = 86_400
    break_glass_justification: Optional[str] = None


class RevokeRequest(BaseModel):
    doctor_id: str


class SearchRequestModel(BaseModel):
    doctor_id: str
    keyword: str = Field(min_length=1, max_length=64)


class RetrieveRequest(BaseModel):
    doctor_id: str
    record_id: str


class EvilModeRequest(BaseModel):
    mode: Literal["honest", "stale", "modified", "withheld"]


class AttackRequest(BaseModel):
    kind: Literal["kga", "plant", "replay", "retrieval_replay", "access_pattern", "all"] = "all"
    mode: Literal["A", "B", "both"] = "both"
    attacker: Literal["outsider", "keyless_server", "insider"] = "outsider"


# --------------------------------------------------------------------------
# Session and state
# --------------------------------------------------------------------------

@router.post("/session/new")
def new_session(req: SessionRequest):
    try:
        config = MedVaultConfig(seed=req.seed, zk_mode=req.zk_mode,
                                ledger_mode=req.ledger_mode)
        world = build_world(config, mode=req.mode)
    except ConsentError as exc:
        raise HTTPException(503, {"reason": exc.reason, "detail": exc.detail})
    SESSION["world"] = world
    return _envelope({"created": True, **world.state()}, [], world)


@router.get("/state")
def state():
    world = _world()
    return _envelope(world.state(), [], world)


@router.post("/store/evil-mode")
def set_evil_mode(req: EvilModeRequest):
    world = _world()
    world.set_evil_mode(req.mode)
    return _envelope({"evil_mode": world.store.evil_mode}, [], world)


# --------------------------------------------------------------------------
# Patient
# --------------------------------------------------------------------------

@router.post("/patient/upload")
def upload(req: UploadRequest):
    world = _world()
    try:
        result, trace = world.upload_record(req.record_id, req.text, req.keywords,
                                            tag=req.tag)
    except (ConsentError, ValueError) as exc:
        raise HTTPException(400, str(exc))
    return _envelope(result, trace, world)


@router.post("/patient/grant")
def grant(req: GrantRequest):
    world = _world()
    scope = (Scope.record_set(req.scope.record_ids) if req.scope.kind == "record_set"
             else Scope.record_tag(req.scope.tag))
    try:
        result, trace = world.grant_scope(
            req.doctor_id, scope, req.expiry_seconds,
            break_glass_justification=req.break_glass_justification,
        )
    except ConsentError as exc:
        raise HTTPException(400, {"reason": exc.reason, "detail": exc.detail})
    return _envelope(result, trace, world)


@router.post("/patient/revoke")
def revoke(req: RevokeRequest):
    world = _world()
    try:
        result, trace = world.revoke_doctor(req.doctor_id)
    except ConsentError as exc:
        raise HTTPException(400, {"reason": exc.reason, "detail": exc.detail})
    return _envelope(result, trace, world)


# --------------------------------------------------------------------------
# Doctor
# --------------------------------------------------------------------------

@router.post("/doctor/search")
def search(req: SearchRequestModel):
    world = _world()
    result, trace = world.search(req.doctor_id, req.keyword)
    return _envelope(result, trace, world)


@router.post("/doctor/retrieve")
def retrieve(req: RetrieveRequest):
    world = _world()
    result, trace = world.retrieve(req.doctor_id, req.record_id)
    return _envelope(result, trace, world)


# --------------------------------------------------------------------------
# Research arm, privacy layer, ledger backend
# --------------------------------------------------------------------------

@router.get("/zk/status")
def zk_status():
    world = _world()
    setup = {}
    meta = CIRCUITS / "build" / "setup_meta.json"
    if meta.exists():
        import json

        setup = json.loads(meta.read_text())
    return _envelope({
        "mode": world.zk.mode,
        "label": world.zk.label,
        "available": ZKAuthorisation.available(),
        "circuit": {k: setup.get(k) for k in
                    ("constraints", "depth", "ptau_power", "zkey_bytes",
                     "trusted_setup", "snarkjs", "circom2")},
        "public_inputs": ["root", "nullifier", "scope_id", "epoch_tag"],
        "private_inputs": ["secret_s", "pathElements", "pathIndices", "nonce"],
        "nullifiers_consumed": world.ledger.nullifier_count(),
        "consent_root": world.ledger.consent_root(world.patient_id).hex(),
    }, [], world)


@router.post("/tree/advance")
def tree_advance(req: TreeRequest):
    """Build the epoch tree, advance to `epoch`, and report the measured cost."""
    world = _world()
    try:
        tree = KeyTree(KeyTreeConfig(depth=req.depth, seed=world.config.seed)).build()
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if req.epoch >= tree.num_epochs:
        raise HTTPException(400, f"epoch must be below {tree.num_epochs} for depth {req.depth}")
    peks = tree.measure_peks() if req.measure_peks else []
    tree.advance_epoch(req.epoch)
    refused = False
    if req.epoch:
        try:
            tree.get_leaf_key(req.epoch - 1)
        except ValueError:
            refused = True
    SESSION["tree"] = tree
    result = {**tree.public_view(), "past_epoch_refused": refused,
              "peks": {"epochs": len(peks),
                       "same_epoch_matches": sum(r["same_epoch_match"] for r in peks),
                       "cross_epoch_matches": sum(r["cross_epoch_match"] for r in peks)}}
    return _envelope(result, tree.trace.to_list(), world)


@router.get("/tree/plot")
def tree_plot():
    """PNG of the measured Gram-Schmidt norm per level for the current tree."""
    tree = SESSION.get("tree")
    if tree is None:
        raise HTTPException(400, "build a tree first: POST /tree/advance")
    FIGURES.mkdir(parents=True, exist_ok=True)
    path = Path(tree.plot_norms(FIGURES / "key_tree_norms.png"))
    return FileResponse(path, media_type="image/png",
                        filename="key_tree_norms.png")


@router.get("/chain/status")
def chain_status():
    world = _world()
    by_operation: dict[str, list[int]] = {}
    for receipt in getattr(world.ledger, "gas_receipts", []):
        by_operation.setdefault(receipt["operation"], []).append(receipt["gas"])
    return _envelope({
        "backend": world.ledger.backend_label,
        "proof_enforced_on_chain": getattr(world.ledger, "require_proof", False),
        "gas": {op: {"calls": len(v), "mean": int(sum(v) / len(v)), "max": max(v)}
                for op, v in by_operation.items()},
        "events": world.ledger.chain_log(),
    }, [], world)


# --------------------------------------------------------------------------
# Auditor / attacker
# --------------------------------------------------------------------------

@router.get("/audit/log")
def audit_log():
    world = _world()
    return _envelope(
        {"audit": world.ledger.audit_view(),
         "chain": world.ledger.chain_log(),
         "state": world.ledger.state_summary()},
        [], world,
    )


def _collect_traces(payload) -> list[dict]:
    """Kept as a thin alias so the router and the demo number events the same way."""
    return collect_traces(payload)


@router.post("/attack/run")
def attack_run(req: AttackRequest):
    world = _world()
    modes = ("A", "B") if req.mode == "both" else (req.mode,)

    if req.kind == "kga":
        result = {mode: run_kga(mode, attacker=req.attacker) for mode in modes}
    elif req.kind == "plant":
        result = {mode: run_plant(mode) for mode in modes}
    elif req.kind == "replay":
        result = {mode: run_replay(mode) for mode in modes}
    elif req.kind == "retrieval_replay":
        result = {mode: run_retrieval_replay(mode) for mode in modes}
    elif req.kind == "access_pattern":
        result = {mode: run_access_pattern(mode) for mode in modes}
    else:
        from .harness import run_all_attacks

        result = run_all_attacks(world.config)
    return _envelope({"kind": req.kind, "attackers": list(ATTACKER_MODELS),
                      "results": result}, _collect_traces(result), world)


@router.get("/eval/tables")
def eval_tables(full: bool = False):
    """Measured tables. `full=true` runs the wide grids (about half a minute)."""
    world = _world()
    result = run_repro(world.config.seed, fast=not full)
    return _envelope(result, [], world)


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------

@router.post("/system/demo-run")
def demo_run(seed: int = 42):
    """The whole sequence in one call (Requirement 13.14, no manual steps)."""
    report = run_demo(MedVaultConfig(seed=seed))
    # R13.11: always saved as "latest"; the golden backup moves only on a clean pass.
    saved = record_run(report)
    SESSION["world"] = build_world(MedVaultConfig(seed=seed, zk_mode="auto"))
    result = {k: v for k, v in report.items() if k != "state"}
    result["trace_saved"] = {"promoted": saved["promoted"], "reason": saved["reason"]}
    return _envelope(result, [], SESSION["world"])


@router.get("/system/demo-trace")
def demo_trace(source: Literal["golden", "latest"] = "golden"):
    """A saved run, replayable without re-executing (R13.11).

    `golden` is the pinned, known-good run; `latest` is the most recent live run,
    which may have failed.
    """
    report = load_report(demo_module.GOLDEN_TRACE if source == "golden"
                         else demo_module.LATEST_TRACE)
    if report is None:
        raise HTTPException(404, f"no {source} trace saved yet: run the demo once")
    report["replayed_source"] = source
    return _envelope(report, [], _world())


@router.get("/system/meta")
def meta():
    world = _world()
    return {
        "result": {
            "seed": world.config.seed,
            "mode": world.mode,
            "kem_label": world.kem.label(),
            "ledger_backend": world.ledger.backend_label,
            "proof_mode": world.zk.label,
            "gate_policy": world.gateway.gate_policy(),
            "pir": {"slot_size": world.pir.slot_size, "lwe_dim": world.pir.lwe_dim},
            "zk_available": ZKAuthorisation.available(),
            "library_versions": library_versions(),
            "claims": {
                "can_say": [
                    "each finding has a named fix and a regression test",
                    "cost and leakage are measured",
                    "key wrapping and PIR use lattice assumptions",
                ],
                "do_not_say": [
                    "post-quantum system",
                    "PPSEB is Module-LWE",
                    "forward security proven",
                    "revocation recalls downloaded data",
                    "LWE is broken",
                    "production-ready",
                ],
            },
        },
        "trace": [],
        "params": {"n": world.params.n, "q": world.params.q},
    }
