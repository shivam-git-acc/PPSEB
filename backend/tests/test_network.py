"""PATCH 18 §6 — the Network tab's simulator.

The honesty properties these pin down: the doctor's decrypt is real, the
attacker's plaintext is reported only when Decrypt round-trips, the attack path
can reach neither a secret key nor the ground truth, the stolen-key attack
reaches backward only, a garbage key recovers nothing, the stored blobs are
never regenerated, and a timeout is never dressed up as security.
"""

import dataclasses
import inspect

import numpy as np
import pytest

import network as nw
from attacks.end_to_end import PeriodDB
from ppseb.params import derived_m


@pytest.fixture(scope="module")
def session():
    """Three records at period 0, one each at periods 1 and 2."""
    s = nw.NetworkSession(4, 257, seed=18)
    assert s.available, s.unavailable_reason
    s.add_record("diabetes", "Patient A: insulin started")
    s.add_record("asthma", "Patient B: inhaler prescribed")
    s.add_record("melanoma", "Patient C: biopsy scheduled")
    s.advance_period()
    s.add_record("hepatitis", "Patient D: labs pending")
    s.advance_period()
    s.add_record("epilepsy", "Patient E: EEG normal")
    return s


@pytest.fixture(scope="module")
def pk_attack(session):
    return session.attack("public_key", [0, 1, 2])


@pytest.fixture(scope="module")
def stolen_attack(session):
    return session.attack("stolen_key", [0, 1], stolen_period=2)


# --- the honest side ------------------------------------------------------

def test_doctor_decrypt_true_plaintext(session):
    """The doctor holds the key, so every stored record decrypts to its true
    text -- the baseline the attacker's attempt is judged against."""
    for rec in [r for st in session.periods for r in st.records]:
        out = session.doctor_decrypt(rec.record_id)["data"]
        assert out["ok"] is True, rec.record_id
        assert out["plaintext"] == rec.text == out["true_plaintext"]
    # Reaching back to an earlier period uses a key forward security says is
    # deleted; the simulator says so rather than implying the scheme allows it.
    old = session.doctor_decrypt(0)["data"]
    assert old["older_than_current"] and "deletes" in old["forward_security_note"]


def test_honest_search_is_correct(session):
    """The verifier finds the right record and rejects a keyword nobody stored,
    using no secret."""
    hit = session.search("epilepsy")["data"]          # stored at the current period
    assert hit["N0"] == hit["true_matches"][0] and hit["correct"]
    assert hit["verifier_used_secret"] is False
    miss = session.search("glaucoma")["data"]
    assert miss["N0"] is None and miss["correct"]


# --- the attacks ----------------------------------------------------------

def test_attacker_keyword_recovery(pk_attack):
    """At the paper's parameters the public key alone labels every record."""
    assert [p["period"] for p in pk_attack["periods"]] == [0, 1, 2]
    for p in pk_attack["periods"]:
        assert p["outcome"] == nw.OUTCOME_RECOVERED
        assert p["recovered"] == p["total"]
        for row in p["rows"]:
            assert row["recovered"] == [row["true_disease"]] and row["correct"]


def test_attacker_plaintext_gated(session, pk_attack, monkeypatch):
    """Plaintext appears only where Decrypt actually round-tripped."""
    for p in pk_attack["periods"]:
        for row in p["rows"]:
            assert (row["plaintext"] is not None) == row["level3"]
            if row["level3"]:
                assert row["plaintext"] == row["true_plaintext"]

    def broken(*a, **kw):
        raise RuntimeError("decode bound exceeded")

    monkeypatch.setattr(nw, "decrypt_record", broken)
    out = session.attack("public_key", [1])
    row = out["periods"][0]["rows"][0]
    assert row["correct"], "keyword recovery must stand on its own"
    assert row["level3"] is False and row["plaintext"] is None
    assert "No record plaintext decrypted" in out["conclusion"]


def test_period_checkbox_scope(session):
    """Only the ticked periods are attacked, and a stolen key cannot reach
    forward to a period at or after the theft."""
    out = session.attack("public_key", [1])
    assert [p["period"] for p in out["periods"]] == [1]

    with pytest.raises(ValueError, match="BACKWARD only"):
        session.attack("stolen_key", [2], stolen_period=2)
    with pytest.raises(ValueError, match="BACKWARD only"):
        session.attack("stolen_key", [1], stolen_period=1)
    with pytest.raises(ValueError, match="no period"):
        session.attack("public_key", [99])


def test_stolen_key_backward_only(session):
    """§2A's guard, plus: the reconstructed basis really is a basis of
    L_perp_q(pk_i) -- otherwise it is not period i's key at all."""
    for stolen, target in ((1, 1), (1, 2), (0, 0)):
        with pytest.raises(ValueError, match="BACKWARD only"):
            session.stolen_key_attack(stolen, target)
    basis, _method = session.stolen_key_attack(2, 0)
    from ppseb.linalg import mat_mod_mixed
    assert np.all(mat_mod_mixed(session.periods[0].pk, basis, session.q) == 0)


def test_pk_only_no_secret():
    """Structural: nothing in the public-key path can carry a secret, and the
    view handed to an attack carries no plaintext or keyword either."""
    assert not any("sk" in x for x in inspect.signature(nw.NetworkSession.public_key_basis).parameters)
    assert not any("sk" in f.name for f in dataclasses.fields(PeriodDB))
    src = inspect.getsource(nw.NetworkSession.public_key_basis)
    assert ".sk" not in src


def test_stolen_only_stolen_sk():
    """Exactly one secret reaches the stolen-key path, and it is the stolen
    period's key."""
    src = inspect.getsource(nw.NetworkSession.stolen_key_attack)
    reads = [line for line in src.splitlines() if ".sk" in line]
    assert len(reads) == 1 and "stolen_period" in reads[0], reads


def test_stolen_reads_only_stolen_sk(session):
    """Dynamic proof: poison every key except the stolen one and the attack
    still runs. The only casualty is `honest_gs`, the simulator's own
    display-side comparison figure, which is then reported absent."""
    class Poisoned:
        def __array__(self, *a, **kw):
            raise AssertionError("the attack read a key it does not hold")
        def __getitem__(self, item):
            raise AssertionError("the attack read a key it does not hold")

    real = {st.period: st.sk for st in session.periods}
    try:
        for st in session.periods:
            if st.period != 2:
                st.sk = Poisoned()
        out = session.attack("stolen_key", [0, 1], stolen_period=2)
    finally:
        for st in session.periods:
            st.sk = real[st.period]
    assert all(p["outcome"] != "error" for p in out["periods"]), out["periods"]
    assert any(p["recovered"] > 0 for p in out["periods"])
    assert all(p["honest_gs"] is None for p in out["periods"])


def test_attacker_view_carries_no_truth(session):
    """The data handed to an attack has no keyword, no plaintext, no key."""
    view = session._attacker_view(0)
    assert view.records == () and view.legit_trap_demo == {}
    assert not any("sk" in f.name for f in dataclasses.fields(type(view)))
    blob = repr(view.CT) + repr(view.CM)
    for rec in session.periods[0].records:
        assert rec.keyword not in blob and rec.text not in blob


def test_garbage_control_recovers_nothing(session):
    """A BKZ'd basis of an unrelated lattice must label nothing; otherwise the
    search is not discriminating and no recovery means anything."""
    out = session.attack("public_key", [0, 1], control=True)
    assert all(p["recovered"] == 0 for p in out["periods"])
    assert all(not row["correct"] and not row["level3"]
               for p in out["periods"] for row in p["rows"])
    assert "must be zero" in out["conclusion"]


def test_frozen_cloud_immutable(session, pk_attack, stolen_attack):
    """The attacks read the doctor's stored blobs; they never regenerate them."""
    session._assert_cloud_frozen()
    for st in session.periods:
        ct_before, cm_before = st.ct_hash, st.cm_hash
        st.refreeze()
        assert (st.ct_hash, st.cm_hash) == (ct_before, cm_before)


def test_comparison_strip(session, stolen_attack):
    """Every stolen-key period says whether the public key alone would have
    recovered it, so the demo can never imply the theft was needed when it was
    not. GOLD only when the public key failed and the stolen key won."""
    for p in stolen_attack["periods"]:
        assert isinstance(p["pk_only_also_recovers"], bool)
        assert p["forward_security_break"] == (p["recovered"] > 0 and not p["pk_only_also_recovers"])
        if p["pk_only_also_recovers"]:
            assert "added nothing" in p["comparison_note"]
            assert not p["forward_security_break"]
    # The public-key attack is not given a comparison against itself.
    plain = session.attack("public_key", [0])
    assert "pk_only_also_recovers" not in plain["periods"][0]


# --- parameters -----------------------------------------------------------

def test_param_selector_derives_m():
    """m = 2n*ceil(log2 q) for every offered pair, derived not cached."""
    opts = nw.parameter_options()
    assert opts["paper_default"] == [4, 257]
    seen = {(o["n"], o["q"]): o["m"] for o in opts["options"]}
    assert len(seen) == len(nw.N_CHOICES) * len(nw.Q_CHOICES)
    for (n, q), m in seen.items():
        assert m == derived_m(n, q)
    assert seen[(4, 257)] != seen[(16, 40961)]


def test_param_correctness_gate():
    """An (n, q) the scheme cannot support is reported unavailable with a
    reason -- never run as a broken demo."""
    bad = nw.NetworkSession(4, 4099, seed=3)       # 4099 = 3 (mod 4), 4 | n
    assert bad.available is False and "H2" in bad.unavailable_reason
    assert bad.periods == []
    with pytest.raises(RuntimeError):
        bad.add_record("diabetes", "x")
    for o in nw.parameter_options()["options"]:
        assert o["available"] == (nw.h2_valid(o["n"], o["q"]) is None)

    good = nw.NetworkSession(4, 257, seed=18)
    assert good.available and all(good.gate[c] for c in nw.GATE_CHECKS)


def test_param_timeout_not_secure(session):
    """A budget-exhausted attack is 'unmeasured', never secure."""
    out = session.attack("public_key", [0], budget_s=1e-6)
    p = out["periods"][0]
    assert p["timed_out"] and p["outcome"] == nw.OUTCOME_TIMEOUT
    assert "secure" not in p["outcome"]
    assert "UNMEASURED, not secure" in out["conclusion"]
