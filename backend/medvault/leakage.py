"""Access-pattern leakage, before and after (deck finding 6; S3).

The mid-sem ledger lab (`attacks/ledger.py`) showed two attacks on PPSEB's
public search log: Tier 1 groups records that answer the same trapdoors (no
prior, certain), Tier 2 labels those groups by matching access frequency to a
public prevalence table (statistical). This module runs those *unchanged*
attack functions on logs produced by the MedVault system itself, so the same
attack can be pointed at:

  mode A, chain view   PPSEB as published: trapdoor + matched records on-chain
  mode B, chain view   the hardened chain: one commitment per search, nothing else
  mode B, node view    the search node, which by design (R11.10) sees the token
                       and the matched record ids — measured, not hidden

Every number is reported beside a chance baseline drawn from the same label
distribution, over several seeds, because one seed can tie with chance (that
is what X-T8 turned out to be: see `honest_misses`).
"""

from __future__ import annotations

import random
from statistics import mean

from attacks.ledger import (
    PREVALENCE,
    _weighted,
    group_purity,
    random_baseline,
    score_labeling,
    tier1,
    tier2_label,
)

from .config import MedVaultConfig
from .crypto import sha256
from .envelope import Scope
from .service import build_world


def _tx(i: int, handle: str, matched) -> dict:
    """The shape `attacks/ledger.py` reads: an id, an opaque handle, a match list."""
    return {"tx_id": i, "trapdoor": handle, "matched": list(matched)}


def analyse_view(view: list[dict], record_ids: list[str], truth: dict[str, str], *,
                 seed: int) -> dict:
    """Tier 1 and Tier 2 on one observer's view, scored against the truth.

    The attack functions never receive `truth`; it is used only to score.
    """
    t1 = tier1(view, record_ids)
    t2 = tier2_label(view, PREVALENCE, record_ids)
    scored = score_labeling(t2["labeling"], truth)
    base = random_baseline(t2["labeling"], truth, seed=seed)
    observed = t2["groups"]
    return {
        "transactions": len(view),
        "records_with_any_match": sum(1 for r in record_ids
                                      if t2["observed_counts"].get(r, 0) > 0),
        "observed_groups": len(observed),
        # Tier 1: are the recovered co-access groups single-disease?
        "tier1_purity": group_purity(observed, truth)["purity"],
        "distinct_handles": t1["distinct_trapdoors"],
        # Tier 2: labelling accuracy against a shuffled-label baseline.
        "tier2_accuracy": scored["accuracy"],
        "baseline_mean": round(base["mean"], 4),
        "baseline_p95": round(base["p95"], 4),
        "beats_baseline": bool(scored["accuracy"] is not None
                               and scored["accuracy"] > base["p95"]),
    }


def cover_schedule(real: list[str], overhead: float, rng: random.Random) -> list[str]:
    """Real queries plus `overhead × len(real)` cover queries, interleaved.

    Cover queries are ordinary searches for real dictionary keywords, assigned
    by water-filling: each one goes to the keyword searched least so far, so
    the per-keyword counts move towards flat. This is a batch scheduler: it
    knows the period's real queries in advance. An online scheduler would be
    noisier; the curve is therefore a best case for this mitigation.
    """
    counts = {k: 0 for k in PREVALENCE}
    for k in real:
        counts[k] += 1
    cover = []
    for _ in range(int(round(overhead * len(real)))):
        low = min(counts.values())
        pick = sorted(k for k, c in counts.items() if c == low)[0]
        counts[pick] += 1
        cover.append(pick)
    stream = list(real) + cover
    rng.shuffle(stream)
    return stream


def run_leakage_workload(mode: str, *, seed: int = 42, records: int = 20,
                         queries: int = 300, cover_overhead: float = 0.0) -> dict:
    """One patient, one doctor, `records` records, `queries` searches, in `mode`.

    Records are tagged by drawing from the public prevalence table and queries
    follow the same table, as in the mid-sem lab. In modes A and C the doctor
    builds one trapdoor per keyword and reuses it (as the lab did, to keep
    trapdoor sampling out of the cost); in mode B each search is a fresh,
    signed, nonce-bound request, as the gateway requires.
    """
    config = MedVaultConfig(seed=seed, index_mode=mode, ledger_mode="memory",
                            zk_mode="signed")
    world = build_world(config, mode=mode)
    keywords = _weighted(random.Random(seed), PREVALENCE, records)
    record_ids = [f"rec-{i:03d}" for i in range(records)]
    truth = dict(zip(record_ids, keywords))
    for record_id, keyword in truth.items():
        world.upload_record(record_id, f"dx={keyword}; care plan on file", [keyword])
    world.grant_scope("doctor_a", Scope.record_set(record_ids))
    doctor = world.doctors["doctor_a"]

    query_keywords = _weighted(random.Random(seed + 77), PREVALENCE, queries)
    if cover_overhead:
        query_keywords = cover_schedule(query_keywords, cover_overhead,
                                        random.Random(seed + 991))
    cached = {}
    node_view = []
    for i, keyword in enumerate(query_keywords):
        if mode == "B":
            result, _ = world.search("doctor_a", keyword)
            token = doctor.last_request.token
        else:
            if keyword not in cached:
                cached[keyword] = doctor.build_request(world.index, keyword, nonce=1,
                                                       timestamp=world.ledger.now())
            result, _ = world.submit_request(cached[keyword])
            token = cached[keyword].token
        node_view.append(_tx(i, sha256(token).hex()[:16], result["record_ids"]))

    chain_view = [
        _tx(i, (e.get("public_token") or e["commitment"])[:16], e.get("matched", []))
        for i, e in enumerate(r for r in world.ledger.chain_log()
                              if r.get("type") == "search_commitment_record")
    ]

    # Scoring only: records whose own keyword was searched but which the honest
    # search never returned. At n = 4, q = 257 some trapdoors fail on their own
    # keyword; those records look "never accessed" to every observer.
    queried = set(query_keywords)
    returned = {r for tx in node_view for r in tx["matched"]}
    honest_misses = sorted(r for r, k in truth.items() if k in queried and r not in returned)

    views = {"chain": analyse_view(chain_view, record_ids, truth, seed=seed)}
    if mode == "B":
        views["search_node"] = analyse_view(node_view, record_ids, truth, seed=seed)
    return {"mode": mode, "seed": seed, "records": records, "queries": queries,
            "cover_overhead": cover_overhead, "searches_issued": len(query_keywords),
            "honest_misses": len(honest_misses), "views": views,
            "params": {"n": world.params.n, "q": world.params.q}}


def leakage_sweep(*, seeds: int = 10, records: int = 20, queries: int = 300,
                  base_seed: int = 2100, modes: tuple[str, ...] = ("A", "B")) -> dict:
    """Run the workload over several seeds and summarise each (mode, view)."""
    runs = {mode: [run_leakage_workload(mode, seed=base_seed + k, records=records,
                                        queries=queries)
                   for k in range(seeds)]
            for mode in modes}
    summary = {}
    for mode, results in runs.items():
        for view in results[0]["views"]:
            cells = [r["views"][view] for r in results]
            accs = [c["tier2_accuracy"] for c in cells]
            purities = [c["tier1_purity"] for c in cells if c["tier1_purity"] is not None]
            summary[f"mode_{mode}_{view}"] = {
                "seeds": seeds,
                "tier1_purity_mean": round(mean(purities), 4) if purities else None,
                "tier1_purity_min": round(min(purities), 4) if purities else None,
                "observed_groups_mean": round(mean(c["observed_groups"] for c in cells), 2),
                "records_with_any_match_mean":
                    round(mean(c["records_with_any_match"] for c in cells), 2),
                "tier2_accuracy_mean": round(mean(accs), 4),
                "tier2_accuracy_min": round(min(accs), 4),
                "tier2_accuracy_max": round(max(accs), 4),
                "baseline_mean": round(mean(c["baseline_mean"] for c in cells), 4),
                "beats_baseline": f"{sum(c['beats_baseline'] for c in cells)}/{seeds}",
                "honest_misses_mean": round(mean(r["honest_misses"] for r in results), 2),
            }
    return {"records": records, "queries": queries, "base_seed": base_seed,
            "summary": summary,
            "per_seed": {mode: [{"seed": r["seed"], "honest_misses": r["honest_misses"],
                                 **{f"{v}_{k}": r["views"][v][k]
                                    for v in r["views"]
                                    for k in ("tier1_purity", "tier2_accuracy",
                                              "baseline_p95", "beats_baseline")}}
                                for r in results]
                         for mode, results in runs.items()}}


def cover_query_curve(*, overheads: tuple[float, ...] = (0.0, 0.25, 0.5, 1.0, 2.0, 4.0),
                      seeds: int = 10, records: int = 20, queries: int = 300,
                      base_seed: int = 2100, mode: str = "B",
                      view: str = "search_node") -> list[dict]:
    """Tier 1 / Tier 2 against the residual observer as cover traffic grows.

    Default target: mode B's search node, the party that still sees tokens and
    matches after the fix. Cover queries are real searches, so they cost real
    search time; the overhead column is extra searches per real search.
    """
    rows = []
    for overhead in overheads:
        cells = [run_leakage_workload(mode, seed=base_seed + k, records=records,
                                      queries=queries, cover_overhead=overhead)["views"][view]
                 for k in range(seeds)]
        accs = [c["tier2_accuracy"] for c in cells]
        purities = [c["tier1_purity"] for c in cells if c["tier1_purity"] is not None]
        rows.append({
            "mode": mode, "view": view, "cover_overhead": overhead,
            "extra_searches_per_real_search": overhead, "seeds": seeds,
            "tier2_accuracy_mean": round(mean(accs), 4),
            "tier2_accuracy_min": round(min(accs), 4),
            "tier2_accuracy_max": round(max(accs), 4),
            "baseline_mean": round(mean(c["baseline_mean"] for c in cells), 4),
            "beats_baseline": f"{sum(c['beats_baseline'] for c in cells)}/{seeds}",
            "tier1_purity_mean": round(mean(purities), 4) if purities else None,
        })
    return rows
