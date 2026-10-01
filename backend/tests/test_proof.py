"""PATCH 22 §A.5/§B.6 — analysis of the paper's proof.

Part A computes what Theorem 1 GUARANTEES; part B maps threats against what
the paper's game can express. The risk in both is overclaiming, so the tests
pin the distinctions: a guarantee is not a break, an upper bound is not a
number, and an unmeasured row must never show a figure.
"""

import math

import pytest

from attacks import proof as P
from ppseb.params import derived_m


def test_guarantee_subtracts_loss():
    """The arithmetic the whole of part A rests on."""
    for (n, q) in ((4, 257), (8, 1153), (16, 12289)):
        r = P.reduction_guarantee(n, q, 4.0)
        assert r["m"] == derived_m(n, q)
        assert r["loss_bits"] == pytest.approx(math.log2(2 * r["m"]))
        if r["lwe_bits"] is not None:
            assert r["guaranteed_bits"] == pytest.approx(r["lwe_bits"] - r["loss_bits"])


def test_loss_grows_with_m():
    """A bigger lattice gives away more in the reduction, not less."""
    small = P.reduction_guarantee(4, 257)
    large = P.reduction_guarantee(16, 12289)
    assert large["m"] > small["m"]
    assert large["loss_bits"] > small["loss_bits"]


def test_guarantee_at_paper_params_is_worthless():
    """At the paper's own parameters the theorem guarantees a handful of bits.

    Asserted as a band, not as "vacuous": the measured figure is positive
    (~7 bits), and calling a positive number vacuous would overstate it. What
    it is, is negligible -- of the order of a hundred operations.
    """
    r = P.reduction_guarantee(*P.PAPER_PARAMS, 4.0)
    assert r["paper_params"]
    assert r["guaranteed_bits"] is not None
    assert r["guaranteed_bits"] < P.NEGLIGIBLE_BITS, r
    assert r["negligible"] and not r["meets_target"]
    if r["guaranteed_bits"] > 0:
        assert "VACUOUS" not in r["verdict"], "a positive guarantee must not be called vacuous"
        assert "negligible" in r["verdict"]


def test_upper_bounds_are_not_dressed_as_numbers():
    """Where the fit is out of its trustworthy range the LWE figure is an
    UPPER bound, and that is carried through to the guarantee."""
    r = P.reduction_guarantee(4, 257, 4.0)
    assert r["lwe_is_upper_bound"] is True
    t = P.reduction_table()
    assert "UPPER bounds" in t["estimator_caveat"]
    # A row the estimator cannot reach must report nothing rather than a zero.
    far = [row for row in t["rows"] if row["lwe_beyond_fit"]]
    for row in far:
        assert row["lwe_bits"] is None and row["guaranteed_bits"] is None
        assert "unquantified" in row["verdict"]


def test_backend_labelled():
    r = P.reduction_guarantee(4, 257)
    assert r["backend"] in ("lattice-estimator", "lindner-peikert-fit")
    t = P.reduction_table()
    assert "root-Hermite fit" in t["estimator_caveat"]


def test_guarantee_is_not_claimed_as_a_break():
    """The honesty line must survive: a loose proof is not a broken scheme."""
    t = P.reduction_table()
    assert "not that the scheme is necessarily broken" in t["honesty"]
    assert "separate" in t["honesty"]
    assert "lower the guarantee" in t["first_order_note"]


# --- B. coverage map ------------------------------------------------------

def test_covered_row_is_theorem1():
    """Exactly one threat is inside the model: the one the theorem proves."""
    c = P.coverage_map()
    yes = [r for r in c["rows"] if r["covered"] == "yes"]
    assert len(yes) == 1
    assert "indistinguishability" in yes[0]["threat"].lower()
    assert "Theorem 1" in yes[0]["model_evidence"]
    assert c["covered"] == 1 and c["not_covered"] >= 4


def test_coverage_two_evidence_columns():
    """Every not-covered row carries BOTH an attack pointer and a proof
    pointer, and the two are labelled so analysis is never read as a run."""
    c = P.coverage_map()
    for row in c["rows"]:
        if row["covered"] == "yes":
            continue
        assert row["model_evidence"] and len(row["model_evidence"]) > 40, row["threat"]
        assert row["attack"]["status"] in ("measured", "missing")
        assert row["attack"]["summary"]
        assert row["tab"], row["threat"]
    assert "DEMONSTRATED" in c["column_labels"]["attack"]
    assert "ANALYSIS" in c["column_labels"]["model"]
    assert "not that the scheme is unconditionally insecure" in c["reading_note"]


def test_coverage_pulls_live_results(tmp_path, monkeypatch):
    """A row shows a measured figure only when one was recorded; otherwise it
    asks for the run. It must never invent a number."""
    monkeypatch.setattr(P, "RESULTS_DIR", tmp_path)
    monkeypatch.setattr(P, "EVIDENCE_PATH", tmp_path / "evidence.json")

    empty = P.coverage_map()
    for row in empty["rows"]:
        if row["covered"] == "yes":
            continue
        assert row["attack"]["status"] == "missing"
        assert row["attack"]["summary"].startswith("run the")
        assert not any(ch.isdigit() for ch in row["attack"]["summary"]), row["attack"]
    assert empty["measured_rows"] == 0

    P.record_evidence("kga", {"summary": "recovered 'diabetes' from a 12-word dictionary",
                              "detail": {"dictionary": 12}, "source": "KGA tab"})
    after = P.coverage_map()
    kga = next(r for r in after["rows"] if r["evidence_key"] == "kga")
    assert kga["attack"]["status"] == "measured"
    assert "diabetes" in kga["attack"]["summary"]
    assert after["measured_rows"] == 1
    # Everything else is still honestly empty.
    assert sum(1 for r in after["rows"] if r["attack"]["status"] == "measured") == 1


def test_meta_findings_are_derived_not_asserted():
    """The two headline sentences quote the counts the map actually produced."""
    c = P.coverage_map()
    assert str(c["total"]) in c["meta_findings"][0]
    assert str(c["covered"]) in c["meta_findings"][0]


def test_run_proof_analysis_shape():
    out = P.run_proof_analysis()
    assert out["reduction"]["rows"] and out["coverage"]["rows"]
    assert out["reduction"]["statement"]
