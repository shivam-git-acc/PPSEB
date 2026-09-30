"""PATCH 21 §E — ledger-metadata attacks.

These need no crypto break and no secret, so the tests pin the two things that
could make them dishonest: that the implementation really does lack the checks
being exploited, and that Tier 2's frequency analysis is not quietly reading
the answer it claims to infer.
"""

import inspect
import random

import numpy as np
import pytest

import network as nw
from attacks import ledger as L
from attacks.end_to_end import verify_search
from ppseb.scheme import verify


@pytest.fixture(scope="module")
def lab():
    return L.LedgerLab(records=16, queries=200, seed=2100)


def test_flow_matches_the_paper():
    """The attacks assume no requester authentication and no well-formedness
    check. If this implementation ever grows either, these findings must be
    restated against the paper's spec instead of demonstrated here -- so the
    assumption is a test, not a comment."""
    assert list(inspect.signature(verify).parameters) == ["CT1", "CT2", "Trap", "params", "trace"], \
        "Verify takes a ciphertext and a trapdoor; an identity argument would change the threat model"
    src = (inspect.getsource(nw.NetworkSession.search) + inspect.getsource(verify_search)
           + inspect.getsource(nw.NetworkSession._label_period))
    for word in ("auth", "signature", "permission", "credential"):
        assert word not in src.lower(), f"search path mentions {word!r}: re-check the threat model"


# --- A. replay -----------------------------------------------------------

def test_replay_returns_same_record(lab):
    """A trapdoor captured off the ledger returns exactly what the doctor got."""
    r = L.replay_attack(lab, 0)
    assert r["identical"] and r["replay_matched"] == r["doctor_matched"]
    assert r["replay_matched"], "the captured search matched nothing, so this proves nothing"
    assert len(r["records_fetched"]) == len(r["replay_matched"])
    assert r["control_ok"] and r["control_random_trapdoor_matched"] == []
    assert r["classification"] == "confidentiality"
    assert r["gets_plaintext"] is False, "replay yields ciphertext and identity, never plaintext"


def test_replay_no_secret():
    """The replay path re-submits captured bytes; it reads no key."""
    src = inspect.getsource(L.replay_attack)
    assert ".sk" not in src
    assert not any("sk" in p for p in inspect.signature(L.replay_attack).parameters)


# --- B. leakage ----------------------------------------------------------

def test_tier1_access_counts(lab):
    """The histogram is exactly what the simulated log contains."""
    log = lab.public_log()
    t1 = L.tier1(log, sorted(lab.truth))
    expected = {}
    for tx in log:
        for n_id in tx["matched"]:
            expected[n_id] = expected.get(n_id, 0) + 1
    assert {h["record"]: h["accesses"] for h in t1["histogram"] if h["accesses"]} == expected
    assert t1["transactions"] == len(log)
    assert t1["classification"] == "confidentiality"


def test_tier2_not_circular(lab, monkeypatch):
    """Structural and dynamic: the labeller has no parameter for the truth map,
    and the attack still runs when touching that map would explode."""
    params = list(inspect.signature(L.tier2_label).parameters)
    assert params == ["tx_log", "prevalence", "record_ids"], params
    assert "truth" not in inspect.getsource(L.tier2_label)

    class Poisoned(dict):
        def __getitem__(self, k):
            raise AssertionError("the labeller read the ground truth")
        def get(self, *a, **kw):
            raise AssertionError("the labeller read the ground truth")

    out = L.tier2_label(lab.public_log(), lab.prevalence, sorted(lab.truth))
    assert len(out["labeling"]) == len(lab.truth)
    monkeypatch.setattr(lab, "truth", Poisoned(lab.truth), raising=False)
    again = L.tier2_label(lab.public_log(), lab.prevalence, list(range(len(out["labeling"]))))
    assert len(again["labeling"]) == len(out["labeling"])


SEEDS = (2100, 2101, 2102)
MEASURED_RECORDS, MEASURED_QUERIES = 20, 300


@pytest.fixture(scope="module")
def measured():
    """Tier 2's labelling accuracy is a statistical claim, so it is asserted
    over several seeds rather than one.

    Measured over seeds 2100-2105 at 20 records / 300 queries: accuracy
    0.40-0.95 (mean 0.725) against a chance baseline of ~0.18, beating chance
    in 6/6 runs, while off-distribution runs score 0.00-0.20 (mean 0.067).
    At the smaller 16 records / 200 queries the labelling can collapse to
    exactly 0.000 -- the group-to-prevalence match is positional, so one
    adjacent swap near the top shifts everything after it. That is a real
    limitation of the attack, recorded here rather than tuned away.
    """
    out = []
    for seed in SEEDS:
        on = L.LedgerLab(records=MEASURED_RECORDS, queries=MEASURED_QUERIES, seed=seed)
        off = L.LedgerLab(records=MEASURED_RECORDS, queries=MEASURED_QUERIES, seed=seed,
                          query_dist=L.skewed(L.PREVALENCE))
        out.append((L.tier2(on), L.tier2(off)))
    return out


def test_tier2_beats_baseline(measured):
    """With enough observations, frequency analysis beats chance -- and the
    baseline is genuinely computed, not asserted."""
    for on, _off in measured:
        assert on["baseline"]["trials"] >= 100 and on["baseline"]["mean"] is not None
    beat = [on["accuracy"] > on["baseline"]["p95"] for on, _ in measured]
    assert all(beat), [(o["accuracy"], o["baseline"]["p95"]) for o, _ in measured]
    assert all(on["beats_baseline"] for on, _ in measured)
    mean_acc = sum(on["accuracy"] for on, _ in measured) / len(measured)
    mean_base = sum(on["baseline"]["mean"] for on, _ in measured) / len(measured)
    assert mean_acc - mean_base > 0.2, (mean_acc, mean_base)


def test_tier2_degrades_offdist(measured):
    """When the query distribution is not the attacker's prior, accuracy falls
    sharply. Compared on means, because a single run of a positional match is
    too brittle to compare."""
    on_mean = sum(on["accuracy"] for on, _ in measured) / len(measured)
    off_mean = sum(off["accuracy"] for _, off in measured) / len(measured)
    assert off_mean < on_mean / 2, (on_mean, off_mean)


def test_tier2_reports_failure_honestly():
    """When the observation is degenerate the module says frequency analysis
    did not beat chance, rather than dressing up noise."""
    ids = list(range(8))
    truth = {i: d for i, d in enumerate(list(L.PREVALENCE)[:8])}
    out = L.tier2_label([], L.PREVALENCE, ids)        # an empty ledger: no signal at all
    scored = L.score_labeling(out["labeling"], truth)
    base = L.random_baseline(out["labeling"], truth, seed=1)
    assert scored["accuracy"] <= base["p95"] + 1e-9


def test_partition_is_the_stable_leak(lab):
    """The two halves of Tier 2 behave very differently, and the test says so.

    Recovering WHICH records share a disease needs no prior and is exact at
    every sample size. Naming the disease needs the prevalence ranking and is
    brittle: the groups are matched to that ranking in order, so one adjacent
    swap near the top shifts everything after it. An earlier version of this
    test asserted accuracy rises monotonically with observations; measured, it
    does not (0.15 -> 0.80 -> 0.00 at 10/25/50 queries), so it now asserts the
    property that actually holds.
    """
    rows = L.accuracy_vs_queries(lab, points=(10, 50, 200))
    assert len(rows) == 3
    assert all(r["purity"] == 1.0 for r in rows), rows
    assert all(r["accuracy"] is not None for r in rows)


def test_tier1_recovers_the_partition_without_a_prior(lab):
    """Co-access alone puts every record in a group holding exactly one
    disease -- no prevalence table involved."""
    t1 = L.tier1(lab.public_log(), sorted(lab.truth), lab.truth)
    assert t1["partition_purity"]["purity"] == 1.0, t1["partition"]
    assert sum(len(g) for g in t1["partition"]) == len(lab.truth)
    assert "prevalence" not in inspect.signature(L.tier1).parameters


# --- C. plant ------------------------------------------------------------

def test_plant_matches_all(lab):
    """The crafted entry matches every real trapdoor; a random entry matches
    none. Both halves are needed -- the second is what rules out a permissive
    Verify."""
    r = L.plant_attack(lab, plants=2)
    assert r["planted_matches_every_search"], r["rows"][:2]
    assert r["control_matches_nothing"], r["rows"][:2]
    assert r["valid"]
    for row in r["rows"]:
        assert len(row["planted_hits"]) == 2
        assert row["control_hits"] == []


def test_plant_classified_integrity(lab):
    """A plant poisons results; it reveals no keyword. Mislabelling it as a
    confidentiality break would overstate the finding."""
    r = L.plant_attack(lab, plants=1)
    assert r["classification"] == "integrity / denial of service"
    assert r["leaks_keyword"] is False
    assert "well-formedness" in r["threat_model"] and "Authenticated writes" in r["threat_model"]


def test_universal_ciphertext_shape():
    from ppseb.params import Params, default_params
    b = default_params()
    p = Params(n=4, q=257, sigma=b.sigma, l=30, usability_C=b.usability_C, m=0)
    ct1, ct2 = L.universal_ciphertext(p)
    assert ct1.shape == (p.l,) and ct2.shape == (p.m, p.l)
    assert np.all(ct2 == 0) and np.all(ct1 == p.q // 2)
    rng = np.random.default_rng(0)
    assert all(verify(ct1, ct2, rng.integers(-99, 99, size=p.m).astype(np.int64), p)[0]
               for _ in range(50))


def test_attacks_are_parameter_independent(lab):
    """None of these depends on the lattice being weak: they are access-control
    and well-formedness gaps."""
    assert L.replay_attack(lab)["parameter_independent"]
    assert L.plant_attack(lab, plants=1)["parameter_independent"]
