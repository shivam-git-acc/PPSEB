"""PATCH 21 — attacks on the ledger's metadata, not on the lattice.

None of these needs a crypto break and none of them cares what n and q are.
They exploit the paper's own central design choice -- putting the search step
on a public chain -- together with two checks it never specifies: nothing
authenticates who submits a trapdoor or who fetches a record, and nothing
checks that a stored ciphertext is well formed.

  A. REPLAY        a trapdoor is a public transaction; anyone can re-submit it
                   and pull the same record. Confidentiality.
  B. LEAKAGE       the (trapdoor -> sequence number) log is public, so access
                   counts and co-access are readable by everyone (Tier 1), and
                   matching those counts against a public prevalence table
                   labels encrypted records (Tier 2). Confidentiality.
  C. PLANT         CT2 = 0 with CT1 = floor(q/2)*1 makes y = CT1 for ANY
                   trapdoor, so one crafted entry matches every search.
                   Integrity / denial of service, not confidentiality.

Preconditions, checked rather than assumed (see test_flow_matches_the_paper):
`ppseb.scheme.verify` takes a ciphertext and a trapdoor and nothing else -- no
caller, no signature -- and no code path in search authenticates a requester or
validates a ciphertext's shape. If authentication were ever added to this
implementation these attacks would have to be restated against the paper's
spec instead; the test fails loudly in that case.

Tier 2 is the one that could be fooled into circularity, so the discipline is
in the signatures: `tier2_label` receives the transaction log and a PUBLIC
prevalence table, and has no parameter through which the record -> disease map
could arrive. Its accuracy is always reported beside a random baseline drawn
from the same label distribution; the finding is the gap between them, and if
there is no gap this module says so.
"""

from __future__ import annotations

import hashlib
import itertools
import random
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

import numpy as np

from ppseb.params import Params
from ppseb.scheme import trapdoor, verify

from network import NetworkSession

# An ILLUSTRATIVE public prevalence table: plausible relative ordering, not
# real epidemiology. It stands in for the kind of base-rate table anyone can
# look up -- which is precisely the attacker's advantage here.
PREVALENCE = {
    "diabetes": 0.28, "hypertension": 0.24, "asthma": 0.14, "hepatitis": 0.09,
    "tuberculosis": 0.07, "melanoma": 0.06, "epilepsy": 0.05, "anemia": 0.04,
    "psoriasis": 0.02, "glaucoma": 0.01,
}
DEFAULT_RECORDS = 24
DEFAULT_QUERIES = 400
QUERY_SWEEP = (10, 25, 50, 100, 200, 400)
BASELINE_TRIALS = 400


@dataclass
class Tx:
    """One public transaction: a trapdoor went on-chain, these sequence numbers
    came back. The keyword is NOT part of it -- that is the point."""
    tx_id: int
    trap: np.ndarray
    matched: tuple[int, ...]

    def public_view(self) -> dict:
        digest = hashlib.sha256(np.ascontiguousarray(self.trap).tobytes()).hexdigest()[:8]
        return {"tx_id": self.tx_id, "trapdoor": digest, "matched": list(self.matched)}


def _weighted(rng: random.Random, weights: dict[str, float], k: int) -> list[str]:
    keys = list(weights)
    tot = sum(weights.values())
    probs = [weights[x] / tot for x in keys]
    return [rng.choices(keys, probs)[0] for _ in range(k)]


def skewed(prevalence: dict[str, float], flip: bool = True) -> dict[str, float]:
    """A query distribution deliberately UNLIKE the reference: prevalence
    reversed. Used to show what happens when the attacker's prior is wrong."""
    keys = list(prevalence)
    vals = [prevalence[k] for k in keys]
    return dict(zip(keys, list(reversed(vals)))) if flip else dict(prevalence)


class LedgerLab:
    """A running doctor, a cloud, and the public transaction log their searches
    leave behind."""

    def __init__(self, n: int = 4, q: int = 257, seed: int = 2100,
                 records: int = DEFAULT_RECORDS, queries: int = DEFAULT_QUERIES,
                 prevalence: dict[str, float] = None, query_dist: dict[str, float] = None,
                 build_retries: int = 5):
        self.prevalence = dict(prevalence or PREVALENCE)
        self.query_dist = dict(query_dist or self.prevalence)
        self.seed = seed

        # A noise draw can leave the HONEST doctor's own search broken, and none
        # of these attacks means anything without a working baseline to attack.
        # Rebuild with a fresh seed rather than reporting a setup failure as a
        # finding, and record which seed actually ran.
        self.session = None
        self.build_attempts = []
        for attempt in range(build_retries + 1):
            build_seed = seed + 4093 * attempt
            candidate = NetworkSession(n=n, q=q, seed=build_seed, dictionary=tuple(self.prevalence))
            self.build_attempts.append({"seed": build_seed, "available": candidate.available,
                                        "reason": candidate.unavailable_reason})
            if candidate.available:
                self.session, self.build_seed = candidate, build_seed
                break
        if self.session is None:
            raise RuntimeError(
                f"no usable build in {build_retries + 1} attempts at n={n}, q={q}: "
                f"{self.build_attempts[-1]['reason']}")
        self.params: Params = self.session.params

        # Records are tagged by drawing from the public prevalence table, so the
        # population the attacker reasons about is the one that exists.
        rng = random.Random(self.build_seed)
        for kw in _weighted(rng, self.prevalence, records):
            self.session.add_record(kw, f"dx={kw}; care plan on file")
        self.truth = {r.record_id: r.keyword for r in self.session.periods[0].records}

        # One REAL trapdoor per distinct keyword, matched with the real Verify
        # against the stored ciphertexts. A repeated search re-samples a
        # trapdoor, which costs a SamplePre each time; the query log below
        # replays these measured match sets instead, and `trapdoor_stability`
        # reports how often a fresh draw reproduces its own set.
        self.match_sets: dict[str, tuple[int, ...]] = {}
        self.traps: dict[str, np.ndarray] = {}
        st = self.session.periods[0]
        for kw in self.prevalence:
            trap = trapdoor(st.pk, st.sk, kw, 0, self.session.mu, self.params,
                            random.Random(self.build_seed + int(hashlib.sha256(kw.encode()).hexdigest()[:6], 16)))
            self.traps[kw] = trap
            self.match_sets[kw] = tuple(
                n_id for (n_id, c1, c2) in st.ct_tuple() if verify(c1, c2, trap, self.params)[0])

        self.trapdoor_stability = self._measure_stability()
        self.tx_log: list[Tx] = []
        self.extend_log(queries)

    def _measure_stability(self, draws: int = 2) -> dict:
        """Does a fresh trapdoor for the same keyword reproduce its match set?
        Measured, because the query log depends on it."""
        st = self.session.periods[0]
        same = total = 0
        for kw in list(self.prevalence)[:4]:
            for d in range(draws):
                t = trapdoor(st.pk, st.sk, kw, 0, self.session.mu, self.params,
                             random.Random(self.build_seed + 5000 + d))
                got = tuple(n_id for (n_id, c1, c2) in st.ct_tuple()
                            if verify(c1, c2, t, self.params)[0])
                same += int(got == self.match_sets[kw])
                total += 1
        return {"redraws": total, "reproduced": same, "rate": same / total if total else None}

    def extend_log(self, queries: int) -> None:
        rng = random.Random(self.build_seed + 77 + len(self.tx_log))
        for kw in _weighted(rng, self.query_dist, queries):
            self.tx_log.append(Tx(len(self.tx_log), self.traps[kw], self.match_sets[kw]))

    # -- what the attacker can see -------------------------------------
    def public_log(self) -> list[dict]:
        return [t.public_view() for t in self.tx_log]


# ---------------------------------------------------------------------------
# A. Replay
# ---------------------------------------------------------------------------

def replay_attack(lab: LedgerLab, tx_index: int = 0) -> dict:
    """Re-submit a trapdoor captured from the public ledger.

    Nothing is forged and no secret is read: the SAME trapdoor bytes go through
    the SAME public Verify, and the cloud hands back the record because nothing
    in the paper's flow asks who is asking.
    """
    tx = lab.tx_log[tx_index]
    st = lab.session.periods[0]
    matched = tuple(n_id for (n_id, c1, c2) in st.ct_tuple()
                    if verify(c1, c2, tx.trap, lab.params)[0])
    fetched = [r.public_view() for r in st.records if r.record_id in matched]

    # Control: a random vector in place of a captured trapdoor must return
    # nothing, or "replay works" would just mean "Verify accepts anything".
    rng = np.random.default_rng(lab.seed + 31)
    junk = rng.integers(-64, 64, size=lab.params.m).astype(np.int64)
    junk_matched = tuple(n_id for (n_id, c1, c2) in st.ct_tuple()
                         if verify(c1, c2, junk, lab.params)[0])

    return {
        "tx": tx.public_view(),
        "doctor_matched": list(tx.matched),
        "replay_matched": list(matched),
        "identical": list(matched) == list(tx.matched),
        "records_fetched": fetched,
        "control_random_trapdoor_matched": list(junk_matched),
        "control_ok": len(junk_matched) == 0,
        "classification": "confidentiality",
        "gets_plaintext": False,
        "note": ("The attacker obtains the record's identity and its ciphertext, not its "
                 "plaintext -- decryption still needs a key. Combined with the public-key "
                 "break it would also yield plaintext at these parameters, but replay alone "
                 "does not."),
        "parameter_independent": True,
    }


# ---------------------------------------------------------------------------
# B. Access-pattern leakage
# ---------------------------------------------------------------------------

def tier1(tx_log: list[dict], record_ids: list[int], truth: dict[int, str] = None) -> dict:
    """Certain, no prior needed: counts and co-access straight off the ledger."""
    counts = Counter()
    for tx in tx_log:
        counts.update(tx["matched"])
    co = Counter()
    for tx in tx_log:
        for a, b in itertools.combinations(sorted(set(tx["matched"])), 2):
            co[(a, b)] += 1
    hist = [{"record": r, "accesses": counts.get(r, 0)} for r in sorted(record_ids)]
    hot = sorted(hist, key=lambda x: -x["accesses"])
    return {
        "histogram": hist,
        "hottest": hot[:5],
        "never_accessed": [h["record"] for h in hist if h["accesses"] == 0],
        "co_access": [{"pair": list(k), "together": v} for k, v in co.most_common(12)],
        "distinct_trapdoors": len({tx["trapdoor"] for tx in tx_log}),
        "transactions": len(tx_log),
        # Records answering exactly the same transactions carry the same
        # keyword. No prior, no key -- this is the certain part of the leak.
        "partition": [sorted(g) for g in _partition(tx_log, record_ids)],
        "partition_purity": (group_purity([{"records": sorted(g)} for g in _partition(tx_log, record_ids)], truth)
                             if truth else None),
        "classification": "confidentiality",
    }


def _partition(tx_log: list[dict], record_ids: list[int]) -> list[list[int]]:
    sig: dict[int, set] = {r: set() for r in record_ids}
    for tx in tx_log:
        for n_id in tx["matched"]:
            if n_id in sig:
                sig[n_id].add(tx["tx_id"])
    groups: dict[frozenset, list[int]] = {}
    for r in record_ids:
        groups.setdefault(frozenset(sig[r]), []).append(r)
    return list(groups.values())


def tier2_label(tx_log: list[dict], prevalence: dict[str, float],
                record_ids: list[int]) -> dict:
    """Frequency analysis, from PUBLIC inputs only.

    The parameters are the ledger, a public prevalence table and the record
    identifiers the ledger already exposes. There is deliberately no parameter
    through which the true record -> disease map could arrive.

    Two public signals are used, in this order:

    1. CO-ACCESS. Records answering exactly the same set of transactions are
       answering the same trapdoor, so they carry the same keyword. Grouping on
       that signature recovers the equivalence classes without touching a key.
       A first version skipped this and allocated diseases to a flat frequency
       ranking in blocks sized by prevalence; measured, it did not beat its own
       random baseline (0.300 vs p95 0.302), because the assumed block sizes
       drift from the sizes actually drawn and every record after the drift is
       shifted. The group sizes are observable, so assuming them was the error.
    2. FREQUENCY. Groups are then ranked by access count and matched against
       the prevalence ranking -- the common disease is queried most.

    Ties in count are broken by group size and then by lowest record id, so the
    labelling is deterministic for a given ledger.
    """
    counts = Counter()
    signature: dict[int, frozenset] = {r: set() for r in record_ids}
    for tx in tx_log:
        for n_id in tx["matched"]:
            counts[n_id] += 1
            if n_id in signature:
                signature[n_id].add(tx["tx_id"])
    signature = {r: frozenset(v) for r, v in signature.items()}

    groups: dict[frozenset, list[int]] = {}
    for r in record_ids:
        groups.setdefault(signature[r], []).append(r)

    # Records nobody queried share the EMPTY signature, so they collapse into a
    # single group carrying no frequency signal at all. Ranking that group
    # alongside the observed ones consumed a disease slot and shifted every
    # assignment after it -- measured, that drove accuracy to exactly 0.000 at
    # 50-200 queries while the full log scored 0.750. They are held out and
    # labelled from the tail of the prevalence order instead, and counted, so a
    # reader can see how much of the labelling is a guess rather than a
    # measurement.
    observed = sorted((g for sig, g in groups.items() if counts.get(g[0], 0) > 0),
                      key=lambda g: (-counts.get(g[0], 0), -len(g), min(g)))
    unobserved = sorted((r for sig, g in groups.items() if counts.get(g[0], 0) == 0 for r in g))

    order = sorted(prevalence, key=lambda d: -prevalence[d])
    labeling = {}
    for i, group in enumerate(observed):
        disease = order[i] if i < len(order) else order[-1]
        for r in group:
            labeling[r] = disease
    for j, r in enumerate(unobserved):
        labeling[r] = order[-(1 + min(j, len(order) - 1))]
    ranked = [r for g in observed for r in g] + unobserved
    return {"labeling": labeling, "ranked": ranked, "unobserved": unobserved,
            "groups": [{"records": g, "accesses": counts.get(g[0], 0)} for g in observed],
            "observed_counts": {r: counts.get(r, 0) for r in record_ids}}


def score_labeling(labeling: dict[int, str], truth: dict[int, str]) -> dict:
    hits = sum(1 for r, d in labeling.items() if truth.get(r) == d)
    return {"correct": hits, "total": len(labeling),
            "accuracy": hits / len(labeling) if labeling else None}


def random_baseline(labeling: dict[int, str], truth: dict[int, str], seed: int = 0,
                    trials: int = BASELINE_TRIALS) -> dict:
    """Chance accuracy for the SAME multiset of labels, shuffled over the same
    records. Controlling for the label distribution is what makes the
    comparison meaningful -- guessing "diabetes" everywhere would otherwise
    look like a result."""
    rng = random.Random(seed)
    labels = list(labeling.values())
    records = list(labeling)
    accs = []
    for _ in range(trials):
        rng.shuffle(labels)
        accs.append(sum(1 for r, d in zip(records, labels) if truth.get(r) == d) / len(records))
    return {"mean": float(np.mean(accs)), "p95": float(np.quantile(accs, 0.95)),
            "trials": trials}


def group_purity(groups: list[dict], truth: dict[int, str]) -> dict:
    """Scoring only, computed outside the attack: does each recovered
    co-access group hold exactly one true disease?

    This is the CERTAIN half of the leak and it is stable, unlike labelling
    accuracy. Recovering the partition needs no prior at all -- records
    answering the same trapdoor carry the same keyword -- so it holds however
    the queries happened to fall."""
    pure = sum(1 for g in groups if len({truth[r] for r in g["records"]}) == 1)
    return {"groups": len(groups), "pure": pure,
            "purity": pure / len(groups) if groups else None}


def tier2(lab: LedgerLab, tx_log: list[dict] = None) -> dict:
    log = tx_log if tx_log is not None else lab.public_log()
    ids = sorted(lab.truth)
    out = tier2_label(log, lab.prevalence, ids)
    scored = score_labeling(out["labeling"], lab.truth)
    base = random_baseline(out["labeling"], lab.truth, seed=lab.seed)
    lift = (scored["accuracy"] - base["mean"]) if scored["accuracy"] is not None else None
    beat = bool(scored["accuracy"] is not None and scored["accuracy"] > base["p95"])
    return {
        "queries": len(log), **scored, "baseline": base, "lift": lift,
        "beats_baseline": beat,
        "groups": len(out["groups"]),
        "unobserved_records": len(out["unobserved"]),
        "rows": [{"record": r, "guess": out["labeling"][r], "truth": lab.truth[r],
                  "correct": out["labeling"][r] == lab.truth[r],
                  "accesses": out["observed_counts"][r]} for r in out["ranked"]],
        "purity": group_purity(out["groups"], lab.truth),
        "verdict": ("frequency analysis beats chance" if beat else
                    "frequency analysis did NOT beat chance here"),
        "cascade_note": (
            "Labelling accuracy is brittle by construction: the groups are matched to the "
            "prevalence ranking in order, so ONE adjacent swap near the top shifts every "
            "group after it and the score collapses. Measured here, a prefix in which "
            "hypertension out-drew diabetes (13 vs 8) scored exactly 0.000 while the full "
            "log scored 0.750. Recovering the PARTITION is the stable result; naming the "
            "diseases is the fragile one."),
        "classification": "confidentiality",
    }


def accuracy_vs_queries(lab: LedgerLab, points=QUERY_SWEEP) -> list[dict]:
    """Leakage accumulates: accuracy against the number of observed queries."""
    full = lab.public_log()
    rows = []
    for k in points:
        if k > len(full):
            continue
        r = tier2(lab, full[:k])
        rows.append({"queries": k, "accuracy": r["accuracy"],
                     "baseline": r["baseline"]["mean"], "beats_baseline": r["beats_baseline"],
                     "purity": r["purity"]["purity"], "groups": r["purity"]["groups"]})
    return rows


# ---------------------------------------------------------------------------
# C. Universal-ciphertext plant
# ---------------------------------------------------------------------------

def universal_ciphertext(params: Params) -> tuple[np.ndarray, np.ndarray]:
    """CT2 = 0 makes y = CT1 - Trap^T.0 = CT1 for ANY trapdoor; CT1 = floor(q/2)*1
    puts every coordinate exactly on the decision point, so Verify accepts."""
    return (np.full(params.l, params.q // 2, dtype=np.int64),
            np.zeros((params.m, params.l), dtype=np.int64))


def plant_attack(lab: LedgerLab, plants: int = 1) -> dict:
    """Append crafted entries -- no write authentication, no well-formedness
    check -- and measure what every subsequent search returns."""
    st = lab.session.periods[0]
    real_ct = st.ct_tuple()
    ct1, ct2 = universal_ciphertext(lab.params)

    rng = np.random.default_rng(lab.seed + 99)
    planted, controls = [], []
    for k in range(plants):
        planted.append((9000 + k, ct1, ct2))
        controls.append((9500 + k,
                         rng.integers(0, lab.params.q, size=lab.params.l).astype(np.int64),
                         rng.integers(0, lab.params.q, size=(lab.params.m, lab.params.l)).astype(np.int64)))

    poisoned_ct = real_ct + tuple(planted) + tuple(controls)
    planted_ids = {p[0] for p in planted}
    control_ids = {c[0] for c in controls}

    rows = []
    for kw, trap in lab.traps.items():
        hits = [n_id for (n_id, c1, c2) in poisoned_ct if verify(c1, c2, trap, lab.params)[0]]
        rows.append({
            "keyword": kw,
            "real_hits": [h for h in hits if h not in planted_ids and h not in control_ids],
            "planted_hits": [h for h in hits if h in planted_ids],
            "control_hits": [h for h in hits if h in control_ids],
        })
    every = all(len(r["planted_hits"]) == len(planted) for r in rows)
    none_ctrl = all(not r["control_hits"] for r in rows)
    return {
        "plants": plants, "searches": len(rows), "rows": rows,
        "planted_matches_every_search": every,
        "control_matches_nothing": none_ctrl,
        "valid": bool(every and none_ctrl),
        "classification": "integrity / denial of service",
        "leaks_keyword": False,
        "threat_model": (
            "The paper specifies neither write authentication nor a well-formedness check, "
            "so this succeeds as written. Authenticated writes stop it only while no "
            "patient is compromised; verifying well-formedness stops it even then, because "
            "a malformed ciphertext cannot be proven well formed."),
        "parameter_independent": True,
    }


# ---------------------------------------------------------------------------
# The whole tab, in one call
# ---------------------------------------------------------------------------

def run_ledger_attacks(n: int = 4, q: int = 257, seed: int = 2100,
                       records: int = DEFAULT_RECORDS, queries: int = DEFAULT_QUERIES,
                       plants: int = 2) -> dict:
    started = time.time()
    lab = LedgerLab(n=n, q=q, seed=seed, records=records, queries=queries)
    off = LedgerLab(n=n, q=q, seed=seed, records=records, queries=queries,
                    query_dist=skewed(PREVALENCE))

    matched_dist = tier2(lab)
    off_dist = tier2(off)
    return {
        "config": {"n": n, "q": q, "seed": seed, "records": records, "queries": queries,
                   "plants": plants, "m": lab.params.m, "l": lab.params.l},
        "prevalence": lab.prevalence,
        "trapdoor_stability": lab.trapdoor_stability,
        "ledger_preview": lab.public_log()[:12],
        "replay": replay_attack(lab),
        "tier1": tier1(lab.public_log(), sorted(lab.truth), lab.truth),
        "tier2": matched_dist,
        "tier2_off_distribution": off_dist,
        "tier2_degrades_off_distribution": bool(
            off_dist["accuracy"] is not None and matched_dist["accuracy"] is not None
            and off_dist["accuracy"] < matched_dist["accuracy"]),
        "accuracy_vs_queries": accuracy_vs_queries(lab),
        "plant": plant_attack(lab, plants=plants),
        "tier2_measured_range": (
            "Measured over seeds 2100-2105 at 20 records / 300 queries: labelling accuracy "
            "0.40-0.95 (mean 0.725) against a chance baseline of ~0.18, beating chance in 6/6 "
            "runs; off-distribution runs scored 0.00-0.20 (mean 0.067). At 16 records / 200 "
            "queries it can collapse to exactly 0.000, because groups are matched to the "
            "prevalence ranking positionally and one adjacent swap shifts everything after it. "
            "The partition (Tier 1) was 100% pure in every run at every sample size."),
        "framing": (
            "Classical PEKS leaks the access pattern to one private server. Putting "
            "verification on a public chain broadcasts it to everyone: the paper's "
            "contribution is what makes this leakage public."),
        "runtime_s": time.time() - started,
    }
