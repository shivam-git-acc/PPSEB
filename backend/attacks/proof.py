"""PATCH 22 — analysis of the paper's SECURITY PROOF, not of the scheme.

Two things live here.

A. REDUCTION LOSS. Theorem 1 reduces ciphertext indistinguishability to LWE
   with an explicit loss: the challenger solves LWE with probability about
   p/2m, where the 1/m comes from guessing the break-in period. Read as a
   guarantee that runs

       Adv_IND <= 2m * Adv_LWE   =>   lambda_scheme >= lambda_LWE - log2(2m)

   so the theorem gives away log2(2m) bits. Plugging the paper's own
   parameters through its own bound shows what it actually promises there.

B. COVERAGE MAP. For each threat: the attack in THIS tool that demonstrates it
   is real, and the point in the paper's §5.2 game where the model cannot
   express it. The first column is MEASURED and is pulled from stored results
   -- never invented; a threat with no stored run says "run that tab" instead
   of showing a number. The second column is ANALYSIS of the paper's text, and
   is labelled as such so nobody reads it as a run.

What A is and is not, stated wherever A is shown: a vacuous guarantee means
THIS PROOF promises nothing at these parameters. It is not itself a break --
that is the separate, measured public-key result -- and a scheme can be secure
for reasons a loose proof fails to capture. The implication runs one way.
"""

from __future__ import annotations

import json
import math
import time
from pathlib import Path
from typing import Optional

from ppseb.params import derived_m

from .security_estimate import estimate_lwe_bits

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
EVIDENCE_PATH = RESULTS_DIR / "evidence.json"

# The paper's demonstration parameters, the rest of the grid this lab uses, and
# one realistic row for contrast.
DEFAULT_GRID = ((4, 257), (8, 257), (4, 1153), (8, 4001), (16, 12289), (256, 12289))
PAPER_PARAMS = (4, 257)
TARGET_BITS = 128
# Below this a guarantee is not vacuous in the strict sense but is worthless in
# practice, and saying "vacuous" of a positive number would overstate it. The
# band is named instead.
NEGLIGIBLE_BITS = 40


# ---------------------------------------------------------------------------
# Evidence store — what the other tabs actually measured
# ---------------------------------------------------------------------------

def record_evidence(key: str, payload: dict) -> None:
    """Called by an attack endpoint after a successful run, so the coverage map
    can quote a real number instead of a hardcoded one."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    store = load_evidence()
    store[key] = {**payload, "recorded_at": time.time()}
    tmp = EVIDENCE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(store, indent=2, default=str))
    tmp.replace(EVIDENCE_PATH)


def load_evidence() -> dict:
    if not EVIDENCE_PATH.exists():
        return {}
    try:
        return json.loads(EVIDENCE_PATH.read_text())
    except json.JSONDecodeError:
        return {}


def _boundary_evidence() -> Optional[dict]:
    """The boundary sweep already persists per cell, so its evidence is read
    off disk rather than needing a hook."""
    metas = sorted(RESULTS_DIR.glob("secbound_*.meta.json"), reverse=True)
    for meta_path in metas:
        jsonl = meta_path.with_name(meta_path.name.replace(".meta.json", ".jsonl"))
        if not jsonl.exists():
            continue
        cells, seen = [], set()
        for line in jsonl.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = (rec["cell"]["n"], rec["cell"]["q"])
            if key in seen:
                continue
            seen.add(key)
            cells.append(rec["cell"])
        if not cells:
            continue
        broke = [c for c in cells if c.get("pk_broke")]
        if not broke:
            continue
        betas = [c["pk_beta"] for c in broke if c.get("pk_beta") is not None]
        return {"summary": f"public key alone broke {len(broke)}/{len(cells)} measured cells"
                           + (f" at BKZ block size {min(betas)}" if betas else ""),
                "detail": {"broke": len(broke), "cells": len(cells),
                           "min_beta": min(betas) if betas else None},
                "source": meta_path.name}
    return None


# ---------------------------------------------------------------------------
# A. Reduction loss
# ---------------------------------------------------------------------------

def reduction_guarantee(n: int, q: int, sigma: float = 4.0) -> dict:
    """What Theorem 1 guarantees at (n, q): the LWE hardness it assumes, minus
    the log2(2m) bits its own reduction gives away."""
    m = derived_m(n, q)
    est = estimate_lwe_bits(n, q, sigma, m=m)
    loss = math.log2(2 * m)
    lwe = est["bits_effective"]
    guaranteed = None if lwe is None else lwe - loss
    return {
        "n": n, "q": q, "m": m, "sigma": sigma,
        "paper_params": (n, q) == PAPER_PARAMS,
        "lwe_bits": lwe,
        "lwe_is_upper_bound": est["is_upper_bound"],
        "lwe_beyond_fit": est["beyond_fit_reach"],
        "backend": est["backend"],
        "loss_bits": loss,
        "guaranteed_bits": guaranteed,
        "vacuous": bool(guaranteed is not None and guaranteed <= 0),
        "meets_target": bool(guaranteed is not None and guaranteed >= TARGET_BITS),
        "negligible": bool(guaranteed is not None and 0 < guaranteed < NEGLIGIBLE_BITS),
        "verdict": (
            "unquantified by this estimator" if guaranteed is None else
            "VACUOUS — guarantees nothing" if guaranteed <= 0 else
            f"negligible — about 2^{guaranteed:.0f} operations" if guaranteed < NEGLIGIBLE_BITS
            else f"below {TARGET_BITS}" if guaranteed < TARGET_BITS else f"≥ {TARGET_BITS}"),
        "note": est.get("note_reach"),
    }


def reduction_table(grid=DEFAULT_GRID, sigma: float = 4.0) -> dict:
    rows = [reduction_guarantee(n, q, sigma) for (n, q) in grid]
    paper = next((r for r in rows if r["paper_params"]), None)
    quantified = [r for r in rows if r["guaranteed_bits"] is not None]
    statement = None
    if paper and paper["guaranteed_bits"] is not None:
        bound = "at most " if paper["lwe_is_upper_bound"] else ""
        statement = (
            f"At the paper's own demonstration parameters (n={paper['n']}, q={paper['q']}, "
            f"m={paper['m']}), Theorem 1's reduction gives away log2(2m) = "
            f"{paper['loss_bits']:.1f} bits, leaving {bound}{paper['guaranteed_bits']:.1f} bits "
            f"of guaranteed security — roughly 2^{paper['guaranteed_bits']:.0f} operations, "
            f"which is work you could do by hand. The theorem is not wrong; at these "
            f"parameters it simply promises nothing worth having.")
    return {
        "rows": rows, "statement": statement,
        "target_bits": TARGET_BITS,
        "first_order_note": (
            "Only the explicit 2m factor the paper states is accounted for. Any further "
            "loss terms -- hash-query counts, for instance -- would lower the guarantee "
            "further, never raise it."),
        "honesty": (
            "This is what the THEOREM guarantees, which is a different claim from what we "
            "measured to break. A vacuous guarantee means this proof is empty at these "
            "parameters, not that the scheme is necessarily broken; the measured break is "
            "the separate, demonstrated result on the Public-Key tab. The implication runs "
            "one way."),
        "estimator_caveat": (
            "The LWE figure comes from a root-Hermite fit, not a full lattice estimator "
            "(no Sage in this environment). At small dimensions the fit overstates "
            "difficulty, so rows below its trustworthy range are reported as UPPER bounds "
            "-- which makes the guarantee at the paper's parameters an upper bound too."),
        "quantified": len(quantified), "total": len(rows),
    }


# ---------------------------------------------------------------------------
# B. Coverage map
# ---------------------------------------------------------------------------

# Each row: the threat, where its demonstration lives, and the point in the
# paper's §5.2 game that cannot express it. `evidence_key` indexes the store;
# `tab` is what to run when it is empty.
THREATS = [
    {
        "threat": "Ciphertext indistinguishability",
        "evidence_key": None, "tab": None,
        "covered": "yes",
        "model_evidence": "Theorem 1 proves exactly this property, under decision-LWE.",
        "attack_note": "Not attacked — this is the property the paper proves.",
    },
    {
        "threat": "Key recovery from the public key",
        "evidence_key": "public_key_break", "tab": "Public-Key",
        "covered": "no",
        "model_evidence": ("The game's setup assumes decision-LWE is hard (§5.2). At the "
                           "paper's own parameters that premise does not hold, so the "
                           "theorem's hypothesis fails rather than its logic."),
    },
    {
        "threat": "Offline keyword guessing",
        "evidence_key": "kga", "tab": "KGA",
        "covered": "no",
        "model_evidence": ("The game offers Hash, Trapdoor, Break-in, Challenge and Guess "
                           "oracles, but defines no advantage for recovering the keyword "
                           "behind a trapdoor — the notion is absent, not lost."),
    },
    {
        "threat": "Universal-ciphertext forgery",
        "evidence_key": "plant", "tab": "Ledger",
        "covered": "no",
        "model_evidence": ("There is no ciphertext-submission oracle: the game is passive "
                           "IND-CKA, so an adversary that WRITES a crafted index entry is "
                           "outside what it can express."),
    },
    {
        "threat": "Trapdoor replay",
        "evidence_key": "replay", "tab": "Ledger",
        "covered": "no",
        "model_evidence": ("Nothing in the game or the scheme authenticates who submits a "
                           "trapdoor or who fetches a record, so replay is not a violation "
                           "of any modelled property."),
    },
    {
        "threat": "Access-pattern leakage",
        "evidence_key": "leakage", "tab": "Ledger",
        "covered": "no",
        "model_evidence": ("The game says nothing about on-chain observability and models "
                           "no leakage function, so what the public ledger reveals is "
                           "invisible to it."),
    },
    {
        "threat": "Forward security as a proven property",
        "evidence_key": "forward_security", "tab": "Forward Security",
        "covered": "partial",
        "model_evidence": ("A break-in phase appears in the game, but Theorem 1 concludes "
                           "indistinguishability; one-wayness of the key evolution is "
                           "asserted, never proven as its own statement."),
    },
]


def coverage_map() -> dict:
    """Rows built from stored results. A missing result produces a prompt to
    run that tab, never a fabricated figure."""
    store = load_evidence()
    boundary = _boundary_evidence()
    rows = []
    for t in THREATS:
        key = t["evidence_key"]
        if key is None:
            attack = {"status": "n/a", "summary": t.get("attack_note")}
        else:
            rec = store.get(key)
            if rec is None and key == "public_key_break" and boundary:
                rec = boundary
            if rec:
                attack = {"status": "measured", "summary": rec.get("summary"),
                          "detail": rec.get("detail"), "source": rec.get("source"),
                          "recorded_at": rec.get("recorded_at")}
            else:
                attack = {"status": "missing",
                          "summary": f"run the {t['tab']} tab to populate this"}
        rows.append({**{k: v for k, v in t.items() if k != "attack_note"}, "attack": attack})

    covered = [r for r in rows if r["covered"] == "yes"]
    not_covered = [r for r in rows if r["covered"] == "no"]
    measured = [r for r in rows if r["attack"]["status"] == "measured"]
    return {
        "rows": rows,
        "covered": len(covered), "not_covered": len(not_covered), "total": len(rows),
        "measured_rows": len(measured),
        "column_labels": {
            "attack": "DEMONSTRATED — measured in this tool",
            "model": "ANALYSIS — argued from the paper's text, not executed",
        },
        "meta_findings": [
            f"Of {len(rows)} threats, the paper's security game expresses {len(covered)}: "
            f"the one it proves. The rest fall outside the game entirely.",
            "And the property it does prove carries a negligible guarantee at the parameters "
            "the paper evaluates -- single-digit bits, not zero -- so the proof both covers "
            "little and promises almost nothing where it covers.",
        ],
        "reading_note": (
            "\"No\" means the paper's game cannot express the threat — not that the scheme "
            "is unconditionally insecure. For key recovery specifically the game's premise "
            "(LWE hard) is what fails at these parameters, not the proof's reasoning."),
    }


def run_proof_analysis(grid=DEFAULT_GRID, sigma: float = 4.0) -> dict:
    return {"reduction": reduction_table(grid, sigma), "coverage": coverage_map(),
            "generated_at": time.time()}
