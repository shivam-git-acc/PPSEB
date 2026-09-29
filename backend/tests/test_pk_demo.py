"""PATCH 16 §6 — public-key-only disease recovery."""

import random

import numpy as np
import pytest

from attacks import pk_demo as demo
from attacks.end_to_end import DICTIONARY
from ppseb.params import Params


@pytest.fixture(scope="module")
def result():
    return demo.run_public_key_demo(seed=1600)


def test_recovered_matches_truth(result):
    """At the paper's parameters the recovered labels ARE the true diseases."""
    assert result["attack"]["total"] == len(result["records"])
    assert result["attack"]["recovered"] == result["attack"]["total"]
    for row in result["attack"]["rows"]:
        assert row["recovered"] == [row["true_disease"]]
        assert row["correct"]


def test_garbage_control_recovers_nothing(result):
    """A BKZ'd basis of an unrelated lattice must label nothing -- otherwise the
    recovery would be an artifact of a permissive search."""
    assert result["control"]["recovered"] == 0
    assert all(not d["matched"] for d in result["control"]["per_disease"].values() if "error" not in d)


def test_pk_demo_no_secret(monkeypatch):
    """Structural and dynamic: the attack path has no channel for a secret key,
    and the run completes even when touching the honest key would explode."""
    import inspect
    from attacks import end_to_end

    params = list(inspect.signature(demo.label_records).parameters)
    assert not any("sk" in name for name in params), params
    assert not any("sk" in f.name for f in __import__("dataclasses").fields(end_to_end.PeriodDB))

    class Poisoned:
        def __array__(self, *a, **kw):
            raise AssertionError("the public-key demo touched the secret key")
        def __getitem__(self, item):
            raise AssertionError("the public-key demo touched the secret key")

    real_build = demo.build_frozen_history

    def poisoned_build(*args, **kwargs):
        history, pk, _sk, mu, u = real_build(*args, **kwargs)
        return history, pk, Poisoned(), mu, u

    monkeypatch.setattr(demo, "build_frozen_history", poisoned_build)
    out = demo.run_public_key_demo(seed=1600, records=4)
    assert out["attack"]["recovered"] >= 1


def test_level3_gated(monkeypatch, result):
    """Plaintext recovery is reported only when Decrypt actually round-trips."""
    for row in result["level3"]:
        assert (row["recovered_plaintext"] is not None) == row["ok"]
    if any(r["ok"] for r in result["level3"]):
        assert "plaintext also decrypted" in result["conclusion"]

    def broken_decrypt(*a, **kw):
        raise RuntimeError("decode bound exceeded")

    monkeypatch.setattr(demo, "decrypt_record", broken_decrypt)
    out = demo.run_public_key_demo(seed=1600, records=4)
    assert all(not r["ok"] and r["recovered_plaintext"] is None for r in out["level3"])
    assert "did NOT decrypt" in out["conclusion"]
    assert out["attack"]["recovered"] >= 1, "keyword recovery must stand on its own"


def test_dictionary_public(result):
    """The dictionary is an attacker input, and carries no ground truth into the attack."""
    assert result["dictionary"] == list(demo.DISEASE_DICTIONARY)
    assert {r["true_disease"] for r in result["records"]} <= set(result["dictionary"])
    assert "dictionary" not in result["withheld_from_attacker"]
    assert any("sk" in item for item in result["withheld_from_attacker"])


def test_attacker_inputs_declared(result):
    assert result["basis_on_lattice"] is True
    assert result["norms"]["recovered_basis_gs"] > 0
    assert any("public key" in i for i in result["attacker_inputs"])


def test_h2_collisions_detected():
    """The colliding pair PATCH 13 measured must be reported, so an ambiguous
    label is never scored as an attack failure."""
    p = Params(n=4, q=257, sigma=4.0, l=10, m=0)
    assert demo.h2_collisions(demo.DISEASE_DICTIONARY, 0, p) == []
    assert ["cirrhosis", "laryngitis"] in demo.h2_collisions(DICTIONARY, 2, p)


def test_collision_ambiguity_not_counted_as_recovery():
    labels = {"per_record": {0: ["cirrhosis", "laryngitis"], 1: ["asthma"]}}
    scored = demo._score(labels, {0: "cirrhosis", 1: "asthma"}, [["cirrhosis", "laryngitis"]])
    assert scored["recovered"] == 1 and scored["ambiguous"] == 1
    assert scored["rows"][0]["collision_ambiguous"] and not scored["rows"][0]["correct"]


def test_doctor_decryption_reported_per_record(result):
    """The honest doctor's own decryption of the SAME records, so an attacker's
    plaintext failure can be told apart from the scheme failing at these
    parameters."""
    per_record = result["honest_decrypt"]
    assert len(per_record) == len(result["records"])
    assert all(isinstance(v, bool) for v in per_record.values())
    assert result["honest_decrypt_count"] == sum(1 for v in per_record.values() if v)
    for row in result["level3"]:
        assert isinstance(row["doctor_ok"], bool)
        assert row["bits"] > 0
    assert "honest doctor using the TRUE secret key" in result["conclusion"]


def test_doctor_decrypt_uses_the_secret_key_not_the_attack_basis(monkeypatch):
    """The doctor's column must come from the honest key inside history
    construction, so breaking the attacker's decrypt cannot change it."""
    def broken_decrypt(*a, **kw):
        raise RuntimeError("attacker decrypt disabled")

    monkeypatch.setattr(demo, "decrypt_record", broken_decrypt)
    out = demo.run_public_key_demo(seed=1600, records=4)
    assert all(not r["ok"] for r in out["level3"])
    assert out["honest_decrypt_count"] >= 1, "the doctor's own decryption should be unaffected"
