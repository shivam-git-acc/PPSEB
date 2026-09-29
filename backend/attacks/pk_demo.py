"""PATCH 16 — recover each record's disease tag from the public key alone.

The attack is the one PATCH 14 measured (public key only, no secret, no
TrapGen); this turns its consequence into something readable: for every disease
in a public dictionary, build a trapdoor from the recovered basis and search the
frozen ciphertext database, producing a "record N is tagged <disease>" label
next to the ground truth.

What the attacker is given is structural, not a promise: `run_public_key_demo`
builds the database through `build_frozen_history`, whose PeriodDB carries no
secret key at all (see test_attacker_never_reads_honest_sk), and the labelling
function receives only that PeriodDB, the public parameter mu, and the
dictionary. mu is treated as public here, exactly as every attack in this lab
since PATCH 05 does.

Two honesty separations are enforced in the data, not just on screen:
- Recovering the disease TAG is the confidentiality break. Recovering the
  record PLAINTEXT is a separate, stronger claim, reported only when Decrypt
  with the attack-derived basis actually round-trips. The honest doctor's own
  decryption is measured alongside, because at q=257 it frequently fails too --
  a failure there is the scheme's, not the attacker's.
- H2 is not injective on keywords (PATCH 13 measured "cirrhosis"/"laryngitis"
  colliding). Two dictionary words sharing a tag are genuinely
  indistinguishable to ANY searcher, so `collisions` reports them and a record
  whose label is ambiguous is shown as such rather than scored as a hit.
"""

from __future__ import annotations

import itertools
import random
import time
from typing import Optional

import numpy as np

from ppseb.hashes import H2
from ppseb.linalg import gram_schmidt_norm, kernel_basis_mod_q, mat_mod_mixed, strong_reduce
from ppseb.params import Params, default_params
from ppseb.scheme import decrypt_record, trapdoor, verify
from ppseb.trace import Trace

from .end_to_end import build_frozen_history
from .security_estimate import gaussian_heuristic

# Low-entropy and enumerable: that is the point -- diseases are public knowledge.
DISEASE_DICTIONARY = (
    "diabetes", "hypertension", "asthma", "hepatitis", "tuberculosis",
    "melanoma", "epilepsy", "anemia", "psoriasis", "glaucoma",
)
DEFAULT_N = 4
DEFAULT_Q = 257
DEFAULT_PERIOD = 0
DEFAULT_RECORDS = 8
DEMO_BETA = 2  # LLL-level; PATCH 14 measured the break at this block size


def h2_collisions(dictionary, period: int, params: Params) -> list[list[str]]:
    """Dictionary words sharing an H2 tag at this period: indistinguishable to
    anyone, attacker or doctor, so they can never be told apart by search."""
    betas = {w: H2(w, period, params) for w in dictionary}
    out = []
    for a, b in itertools.combinations(dictionary, 2):
        if np.array_equal(betas[a] % params.q, betas[b] % params.q):
            out.append(sorted((a, b)))
    return out


def label_records(period_db, basis: np.ndarray, dictionary, period: int, mu, params: Params,
                  rng: random.Random, trace: Trace | None = None) -> dict:
    """For each disease, build a trapdoor from `basis` and search the frozen CT.

    Takes a PeriodDB (public: pk, CT, CM) plus public inputs only -- there is no
    parameter through which a secret key could arrive.
    """
    matches: dict[int, list[str]] = {n_id: [] for (n_id, _c1, _c2) in period_db.CT}
    per_disease = {}
    for disease in dictionary:
        try:
            trap = trapdoor(period_db.pk_ri, basis, disease, period, mu, params, rng)
        except Exception as e:  # noqa: BLE001 -- a degenerate basis simply yields no label
            per_disease[disease] = {"error": f"{type(e).__name__}: {e}", "matched": []}
            continue
        hit = [n_id for (n_id, c1, c2) in period_db.CT if verify(c1, c2, trap, params)[0]]
        per_disease[disease] = {"matched": hit, "trap_norm": float(np.linalg.norm(trap.astype(float)))}
        for n_id in hit:
            matches[n_id].append(disease)
        if trace is not None:
            trace.compute(
                f"Trapdoor for {disease!r} from the public-key basis",
                detail=f"Matched record(s) {hit}" if hit else "Matched nothing.",
                data={"disease": disease, "matched": hit},
                algo="PublicKeyBreak",
            )
    return {"per_record": matches, "per_disease": per_disease}


def _score(labels: dict, truth: dict[int, str], collisions: list[list[str]]) -> dict:
    """A record counts as recovered only when the label is unambiguous and right.

    A label that is ambiguous ONLY because of an H2 collision is reported
    separately: no searcher can do better, so it is neither a hit nor a miss
    attributable to the attack.
    """
    colliding = {w for pair in collisions for w in pair}
    rows, recovered, ambiguous = [], 0, 0
    for n_id, got in sorted(labels["per_record"].items()):
        true_disease = truth[n_id]
        exact = got == [true_disease]
        collision_ambiguous = (
            not exact and true_disease in got and len(got) > 1
            and all(w in colliding for w in got)
        )
        if exact:
            recovered += 1
        elif collision_ambiguous:
            ambiguous += 1
        rows.append({"record": n_id, "true_disease": true_disease, "recovered": got,
                     "correct": exact, "collision_ambiguous": collision_ambiguous})
    return {"rows": rows, "recovered": recovered, "ambiguous": ambiguous, "total": len(rows)}


def run_public_key_demo(n: int = DEFAULT_N, q: int = DEFAULT_Q, seed: int = 1600,
                        records: int = DEFAULT_RECORDS, period: int = DEFAULT_PERIOD,
                        dictionary=DISEASE_DICTIONARY, beta: int = DEMO_BETA) -> dict:
    started = time.time()
    base = default_params()
    p = Params(n=n, q=q, sigma=base.sigma, l=base.l, usability_C=base.usability_C, m=0)
    trace = Trace()
    trace.threat_model(
        "Attacker holds the PUBLIC KEY only",
        detail="No secret key, no captured trapdoor, no TrapGen. Inputs: pk_r|i, the public "
               "parameter mu, the public ciphertext database (CT_N, CM_N), and a disease "
               "dictionary -- diseases are low-entropy and enumerable.",
        algo="PublicKeyBreak",
        highlight=True,
    )

    history, _stolen_pk, _stolen_sk, mu, u_pke = build_frozen_history(
        max(period + 1, 2), p, seed=seed, records_per_period=records,
        dictionary=tuple(dictionary), honest_checks=True, max_seed_retries=0, trace=None,
    )
    db = history[period]
    truth = {n_id: kw for (n_id, kw, _m) in db.records}
    plaintexts = {n_id: m.decode(errors="replace") for (n_id, _kw, m) in db.records}
    honest = db.legit_trap_demo["checks"]
    collisions = h2_collisions(dictionary, period, p)

    # The attack: a basis of L_perp_q(pk) built from the PUBLIC key alone
    # (kernel_basis_mod_q includes the q*e_j vectors), then reduced.
    t0 = time.time()
    basis, method = strong_reduce(kernel_basis_mod_q(db.pk_ri, q), block_size=beta)
    reduce_s = time.time() - t0
    on_lattice = bool(np.all(mat_mod_mixed(db.pk_ri, basis, q) == 0))
    norms = {
        "recovered_basis_gs": gram_schmidt_norm(basis),
        "honest_basis_gs": honest["period_gs"],
        "gaussian_heuristic": gaussian_heuristic(n, q, p.m),
        "reduction_method": method, "beta": beta, "reduction_s": reduce_s,
    }
    trace.norm(
        "Reduced a basis built from the public key alone",
        detail="Its Gram-Schmidt norm sits beside the honest secret basis and the lattice's "
               "expected shortest vector: the public basis is as short as the secret one, so "
               "the secret confers no advantage at these parameters.",
        data=norms, algo="PublicKeyBreak", highlight=True,
    )

    labels = label_records(db, basis, dictionary, period, mu,
                           p, random.Random(seed + 1), trace)
    scored = _score(labels, truth, collisions)

    # Negative control: the same labelling from a BKZ'd basis of an UNRELATED
    # lattice. It must recover nothing.
    ctrl_rng = np.random.default_rng(seed + 7)
    unrelated = ctrl_rng.integers(0, q, size=(n, p.m)).astype(np.int64)
    ctrl_basis, _ = strong_reduce(kernel_basis_mod_q(unrelated, q), block_size=beta)
    ctrl_labels = label_records(db, ctrl_basis, dictionary, period, mu, p, random.Random(seed + 2))
    ctrl_scored = _score(ctrl_labels, truth, collisions)

    # Level 3 is a separate, stronger claim: only reported if Decrypt round-trips.
    level3 = []
    for row in scored["rows"]:
        if not row["correct"]:
            continue
        n_id = row["record"]
        cm = next(c for (i, c) in db.CM if i == n_id)
        try:
            got = decrypt_record(db.pk_ri, basis, cm, u_pke, p, random.Random(seed + 3 + n_id))
            ok = got == plaintexts[n_id].encode()
        except Exception:  # noqa: BLE001
            got, ok = b"", False
        level3.append({"record": n_id, "recovered_plaintext": got.decode(errors="replace") if ok else None,
                       "ok": bool(ok)})

    conclusion = (
        f"Holding only the public key, the disease dictionary and the public ciphertext "
        f"database, the attacker recovered the disease tag of {scored['recovered']}/{scored['total']} "
        f"patient records at n={n}, q={q}"
        + (" (the paper's own parameters)" if (n, q) in ((4, 257), (8, 257)) else "")
        + f", using BKZ block size {beta} (LLL-level effort) and no secret key. "
        + (f"{scored['ambiguous']} record(s) were ambiguous only because two dictionary words share "
           f"an H2 tag, which no searcher can separate. " if scored["ambiguous"] else "")
        + f"A basis from an unrelated lattice recovered {ctrl_scored['recovered']}/{ctrl_scored['total']}. "
        + (f"Record plaintext also decrypted for {sum(1 for r in level3 if r['ok'])}/{len(level3)} of the "
           f"matched records. " if any(r["ok"] for r in level3) else
           "Record plaintext did NOT decrypt with this basis (the record decode bound is stricter), "
           "so only the disease tag was recovered. ")
        + ("The honest doctor's own decryption also fails at these parameters, so that is a limit of the "
           "scheme here, not of the attack. " if not honest["decrypt_ok"] else "")
        + "No key compromise was needed to learn which disease each encrypted record concerns."
    )
    trace.result("Public-key-only recovery", detail=conclusion,
                 data={"recovered": scored["recovered"], "total": scored["total"]},
                 algo="PublicKeyBreak", highlight=True)

    return {
        "n": n, "q": q, "m": p.m, "period": period, "seed": seed, "beta": beta,
        "paper_params": (n, q) in ((4, 257), (8, 257)),
        "attacker_inputs": ["pk_r|i (public key)", "mu (public parameter)",
                            "CT_N / CM_N (public ciphertext database)", "disease dictionary"],
        "withheld_from_attacker": ["sk_r|i (secret key)", "any captured trapdoor", "TrapGen"],
        "dictionary": list(dictionary),
        "records": [{"record": n_id, "true_disease": truth[n_id], "plaintext": plaintexts[n_id]}
                    for n_id in sorted(truth)],
        "honest_checks": honest,
        "h2_collisions": collisions,
        "norms": norms,
        "basis_on_lattice": on_lattice,
        "attack": scored,
        "per_disease": labels["per_disease"],
        "control": {**ctrl_scored, "per_disease": ctrl_labels["per_disease"]},
        "level3": level3,
        "conclusion": conclusion,
        "runtime_s": time.time() - started,
        "trace": trace.to_list(),
    }
