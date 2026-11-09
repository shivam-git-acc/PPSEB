"""The demo, as one callable sequence (PRD §11, Requirement 13).

The UI's "run the demo" button and the demo-flow test both drive this, so what is
rehearsed is exactly what is presented. Each step returns its own result and
trace, and `all_passed` is computed from the step predicates rather than asserted
in prose — if a step's expected outcome does not happen, the demo says so.

Step 4 covers both halves of authorisation: the capability envelope *and* the
Groth16 proof, with a reused proof rejected in the same step. Step 9 runs the
lattice epoch tree, reports measured norms, and erases past-epoch keys. When the
circuit has not been built, step 4 drops to the labelled signed fallback instead
of pretending to be zero-knowledge.
"""

from __future__ import annotations

import argparse
import copy
import json
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

from .config import MedVaultConfig
from .envelope import Scope
from .harness import run_all_attacks
from .key_tree import KeyTree, KeyTreeConfig
from .search import sign_search_request
from .service import DemoWorld, build_world
from .zk import ZKAuthorisation

#: Where the demo's figures go. Gitignored result directory, committed summary.
FIGURES = Path(__file__).resolve().parent.parent / "results" / "figures"


@dataclass
class DemoStep:
    index: int
    title: str
    ok: bool
    result: dict = field(default_factory=dict)
    trace: list[dict] = field(default_factory=list)
    pending: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _step(index: int, title: str, ok: bool, result: dict | None = None,
          trace: list[dict] | None = None, pending: str = "") -> DemoStep:
    return DemoStep(index, title, bool(ok), result or {}, trace or [], pending)


def _proof_summary(world: DemoWorld) -> dict:
    """What an observer may know about the authorisation proof (R6.2)."""
    request = world.doctors["doctor_a"].last_request
    proof = (request.zk_proof if request is not None else None) or {}
    if proof.get("kind") == "groth16":
        inputs = proof.get("public_inputs") or []
        return {"kind": "groth16", "label": world.zk.label,
                "public_inputs": [name for name in
                                  ("root", "nullifier", "scope_id", "epoch_tag")[:len(inputs)]],
                "public_input_count": len(inputs),
                "verify_ms": round(world.zk.last_verification_ms, 2),
                "private": ["secret_s", "pathElements", "pathIndices", "nonce"]}
    return {"kind": "signed", "label": world.zk.label,
            "public_input_count": 0, "private": [],
            "note": "signed consent — not zero knowledge; build the circuit for Groth16"}


def _replay_the_proof(world: DemoWorld) -> tuple[bool, str, list[dict]]:
    """Re-sign the captured request with a fresh nonce and keep its proof.

    Every non-proof gate passes (signature, epoch, nonce, scope), so a rejection
    can only come from the proof or its nullifier.
    """
    agent = world.doctors["doctor_a"]
    request = agent.last_request
    if request is None:
        return False, "no_request", []
    again = copy.copy(request)
    again.nonce = agent.next_nonce()
    again.signature = sign_search_request(agent.signing_key, again.token, again.nonce,
                                          again.epoch, again.timestamp)
    result, trace = world.submit_request(again)
    return bool(result["ok"]), result["reason"], trace


def _concat_traces(*traces: list[dict]) -> list[dict]:
    """Join several operations' events into one 1..N sequence.

    A step that performs two operations (search then retrieve) must still hand the
    UI a single ordered list, or the timeline shows two events numbered 1.
    """
    merged: list[dict] = []
    for trace in traces:
        for event in trace:
            renumbered = dict(event)
            renumbered["step"] = len(merged) + 1
            merged.append(renumbered)
    return merged


def collect_traces(payload) -> list[dict]:
    """Every trace nested in a result, flattened into one 1..N sequence.

    The attack harness returns a trace per attack per mode; appending them as-is
    would number four events as step 1.
    """
    events: list[dict] = []

    def walk(obj) -> None:
        if isinstance(obj, dict):
            trace = obj.get("trace")
            if isinstance(trace, list):
                events.extend(trace)
            for key, value in obj.items():
                if key != "trace":
                    walk(value)
        elif isinstance(obj, list):
            for value in obj:
                walk(value)

    walk(payload)
    return [{**event, "step": index + 1} for index, event in enumerate(events)]


def run_demo(config: MedVaultConfig | None = None, *, world: DemoWorld | None = None
             ) -> dict:
    """Run all nine demo steps against one hardened world."""
    config = config or MedVaultConfig()
    if world is None:
        # The demo proves when it can and says so when it cannot; the core unit
        # tests keep the explicit signed mode for speed and determinism.
        config = replace(config, zk_mode="auto")
    started = time.perf_counter()
    steps: list[DemoStep] = []

    # ---- 1. the three attacks succeed on the original PPSEB ---------------
    attacks = run_all_attacks(config)
    baseline_ok = (
        attacks["kga"]["mode_A"]["outsider"]["success"]
        and attacks["plant"]["A"]["appears_in_search"]
        and attacks["replay"]["A"]["replay_ok"]
    )
    steps.append(_step(
        1, "KGA, plant and replay on the original PPSEB", baseline_ok,
        {
            "kga": attacks["kga"]["mode_A"]["outsider"],
            "plant": attacks["plant"]["A"],
            "replay": attacks["replay"]["A"],
            "access_pattern": attacks["access_pattern"]["A"],
        },
        collect_traces({
            "kga": attacks["kga"]["mode_A"],
            "plant": attacks["plant"]["A"],
            "replay": attacks["replay"]["A"],
            "access_pattern": attacks["access_pattern"]["A"],
        }),
    ))

    # ---- 2. upload encrypted records -------------------------------------
    world = world or build_world(config)
    records = [
        ("rec-lab", "hba1c 7.4 percent", ["diabetes", "blood"], "lab"),
        ("rec-cxr", "chest x-ray clear", ["radiology"], "radiology"),
        ("rec-rx", "metformin 500mg", ["pharmacy"], "pharmacy"),
    ]
    uploads = []
    upload_trace: list[dict] = []
    for record_id, text, keywords, tag in records:
        result, trace = world.upload_record(record_id, text, keywords, tag=tag)
        uploads.append(result)
        upload_trace = trace
    root, version = world.ledger.record_root(world.patient_id)
    steps.append(_step(
        2, "Patient uploads encrypted records and commits the Merkle root",
        bool(root) and version == len(records),
        {"records": uploads, "merkle_root": root.hex(), "version": version},
        upload_trace,
    ))

    # ---- 3. three doctors, three scopes ----------------------------------
    grants = []
    grant_trace: list[dict] = []
    for doctor_id, scope in (
        ("doctor_a", Scope.record_tag("lab")),
        ("doctor_b", Scope.record_tag("radiology")),
        ("doctor_c", Scope.record_set(["rec-rx"])),
    ):
        result, trace = world.grant_scope(doctor_id, scope)
        grants.append(result)
        grant_trace = trace
    envelopes_private = all(
        world.open_envelope_as(agent_id, world.doctors[agent_id].envelope, other)["ok"] is False
        for agent_id in ("doctor_a", "doctor_b", "doctor_c")
        for other in {"doctor_a", "doctor_b", "doctor_c"} - {agent_id}
    )
    steps.append(_step(
        3, "Patient grants three doctors three different scopes",
        all(g["opened_by_recipient"] for g in grants) and envelopes_private,
        {"grants": grants, "envelopes_open_only_for_their_owner": envelopes_private},
        grant_trace,
    ))

    # ---- 4. doctor A searches and retrieves ------------------------------
    search, search_trace = world.search("doctor_a", "diabetes")
    retrieval, retrieval_trace = world.retrieve("doctor_a", "rec-lab")
    proof = _proof_summary(world)
    reused_ok, reused_reason, reused_trace = _replay_the_proof(world)
    steps.append(_step(
        4, "Doctor A searches and retrieves, with integrity checked first",
        search["ok"] and retrieval["ok"] and bool(retrieval.get("plaintext"))
        and not reused_ok,
        {"search": search, "retrieval": {k: v for k, v in retrieval.items()
                                         if k != "plaintext"},
         "proof": proof, "reused_proof": {"accepted": reused_ok,
                                          "reason": reused_reason}},
        _concat_traces(search_trace, retrieval_trace, reused_trace),
    ))

    # ---- 5. the same three attacks fail on the hardened path -------------
    hardened_ok = (
        not attacks["kga"]["mode_B"]["outsider"]["success"]
        and not attacks["kga"]["mode_B"]["keyless_server"]["success"]
        and attacks["kga"]["mode_B"]["insider"]["success"]
        and not attacks["plant"]["B"]["appears_in_search"]
        and not attacks["replay"]["B"]["replay_ok"]
        and not attacks["access_pattern"]["B"]["token_on_chain"]
    )
    steps.append(_step(
        5, "KGA, plant and replay on the hardened path", hardened_ok,
        {
            "kga": attacks["kga"]["mode_B"],
            "plant": attacks["plant"]["B"],
            "replay": attacks["replay"]["B"],
            "access_pattern": attacks["access_pattern"]["B"],
        },
        collect_traces({
            "kga": attacks["kga"]["mode_B"],
            "plant": attacks["plant"]["B"],
            "replay": attacks["replay"]["B"],
            "access_pattern": attacks["access_pattern"]["B"],
        }),
    ))

    # ---- 6. revoke doctor A ---------------------------------------------
    revoked, revoke_trace = world.revoke_doctor("doctor_a")
    stale_search, stale_trace = world.search("doctor_a", "diabetes")
    stale_fetch, _ = world.retrieve("doctor_a", "rec-lab")
    steps.append(_step(
        6, "Patient revokes Doctor A",
        stale_search["reason"] == "stale_epoch" and stale_fetch["reason"] == "stale_epoch",
        {"revocation": revoked, "stale_search": stale_search,
         "stale_retrieval": stale_fetch},
        _concat_traces(revoke_trace, stale_trace),
    ))

    # ---- 7. doctor B still works ----------------------------------------
    surviving, surviving_trace = world.search("doctor_b", "radiology")
    surviving_fetch, _ = world.retrieve("doctor_b", "rec-cxr")
    steps.append(_step(
        7, "Doctor B still works inside their own scope",
        surviving["ok"] and surviving_fetch["ok"],
        {"search": surviving, "retrieval": {k: v for k, v in surviving_fetch.items()
                                            if k != "plaintext"}},
        surviving_trace,
    ))

    # ---- 8. a modified record fails closed ------------------------------
    world.set_evil_mode("modified")
    tampered, tampered_trace = world.retrieve("doctor_b", "rec-cxr")
    world.set_evil_mode("honest")
    recovered, _ = world.retrieve("doctor_b", "rec-cxr")
    steps.append(_step(
        8, "A modified record fails closed, and the honest control recovers",
        (not tampered["ok"]) and tampered["plaintext"] is None and recovered["ok"],
        {"tampered": tampered, "honest_control_ok": recovered["ok"]},
        tampered_trace,
    ))

    # ---- 9. key tree (M7) ------------------------------------------------
    tree = KeyTree(KeyTreeConfig(depth=4, seed=config.seed)).build()
    correctness = tree.check_all_correctness()
    norms = tree.norm_summary()
    peks = tree.measure_peks()
    tree.advance_epoch(6)
    erased_epoch_refused = False
    try:
        tree.get_leaf_key(5)
    except ValueError:
        erased_epoch_refused = True
    plot = None
    try:
        FIGURES.mkdir(parents=True, exist_ok=True)
        plot = str(tree.plot_norms(FIGURES / "key_tree_norms.png"))
    except Exception:  # pragma: no cover - matplotlib is optional
        plot = ""
    steps.append(_step(
        9, "Advance epochs in the lattice key tree",
        all(correctness.values()) and erased_epoch_refused
        and all(row["usable"] for row in norms)
        and all(row["same_epoch_match"] for row in peks)
        and not any(row["cross_epoch_match"] for row in peks),
        {"depth": tree.config.depth, "nodes": len(tree.nodes),
         "params": {"n": tree.config.params.n, "q": tree.config.params.q,
                    "sigma": tree.config.params.sigma, "l": tree.config.params.l},
         "all_nodes_correct": all(correctness.values()),
         "norms_per_level": norms, "current_epoch": tree.current_epoch,
         "frontier": sorted(tree.frontier),
         "past_epoch_refused": erased_epoch_refused,
         "peks": {"same_epoch_matches": sum(r["same_epoch_match"] for r in peks),
                  "cross_epoch_matches": sum(r["cross_epoch_match"] for r in peks),
                  "epochs": len(peks)},
         "claim": "structure and cost measured; no forward-security claim",
         "plot": plot},
        tree.trace.to_list(),
    ))

    elapsed = time.perf_counter() - started
    graded = [s for s in steps if not s.pending]
    return {
        "steps": [s.as_dict() for s in steps],
        "all_passed": all(s.ok for s in graded),
        "passed": sum(1 for s in graded if s.ok),
        "graded": len(graded),
        "pending": [s.index for s in steps if s.pending],
        "elapsed_s": round(elapsed, 2),
        "within_ten_minutes": elapsed < 600,
        "seed": config.seed,
        "mode": world.mode,
        "kem_label": world.kem.label(),
        "ledger_backend": world.ledger.backend_label,
        "proof_mode": world.zk.label,
        "state": world.state(),
    }


# --------------------------------------------------------------------------
# Saved traces (R13.11)
# --------------------------------------------------------------------------

RESULTS = Path(__file__).resolve().parent.parent / "results"
DEFAULT_TRACE = RESULTS / "demo_trace.json"


def save_report(report: dict, output: Path = DEFAULT_TRACE) -> Path:
    """Write the whole demo, traces included, as one JSON file.

    Requirement 13.11: if the live run fails on the day, the traces must be
    replayable from disk. Saving them is the only way that is true, so the demo
    writes this file every time it runs.
    """
    output.parent.mkdir(parents=True, exist_ok=True)
    payload = {k: v for k, v in report.items() if k != "state"}
    payload["saved_by"] = "medvault.demo"
    output.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    return output


def load_report(path: Path = DEFAULT_TRACE) -> dict | None:
    """The saved report, or None when nothing has been recorded yet."""
    if not path.exists():
        return None
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    report["replayed_from"] = str(path)
    report["replayed"] = True
    return report


def main(argv: list[str] | None = None) -> int:
    """`python -m medvault.demo` runs the sequence and saves its traces."""
    parser = argparse.ArgumentParser(description="Run the MedVault-PQ demo and save its traces")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output", type=Path, default=DEFAULT_TRACE)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    report = run_demo(MedVaultConfig(seed=args.seed))
    path = save_report(report, args.output)
    if not args.quiet:
        print(f"wrote {path}")
        print(f"  {report['passed']}/{report['graded']} graded steps passed in "
              f"{report['elapsed_s']}s ({report['proof_mode']})")
        for step in report["steps"]:
            mark = "pending" if step["pending"] else ("ok  " if step["ok"] else "FAIL")
            print(f"  {mark} {step['index']}. {step['title']}")
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":  # pragma: no cover - CLI entry point
    raise SystemExit(main())
