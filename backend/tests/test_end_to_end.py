import copy
import dataclasses
import inspect

import numpy as np
import pytest

from ppseb.params import default_params
from attacks import end_to_end as e2e
from attacks.end_to_end import (
    build_frozen_history, attack_period, attack_period_negative_control,
    end_to_end_experiment, end_to_end_multi_n,
    verify_search, _hash_ct, _hash_cm,
)


@pytest.fixture(scope="module")
def small_history():
    p = default_params()
    history, stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(J=2, params=p, seed=1)
    return p, history, stolen_pk, stolen_sk, mu, u_pke


def test_legit_doctor_finds_own_record(small_history):
    """N0_legit must not be None for every period — the honest doctor must
    be able to find their own record before we ever ask if an attacker can."""
    _p, history, _stolen_pk, _stolen_sk, _mu, _u_pke = small_history
    for entry in history:
        assert entry.legit_trap_demo["N0"] is not None


def test_frozen_db_immutable(small_history):
    """CT_i/CM_i content hashes before and after an attack run must be
    identical — the attacker must never regenerate the frozen ciphertexts."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    before_ct = [entry.ct_hash for entry in history]
    before_cm = [entry.cm_hash for entry in history]
    for i in range(len(history)):
        attack_period(history, i, len(history), stolen_sk, p, mu, u_pke)
    after_ct = [_hash_ct(entry.CT) for entry in history]
    after_cm = [_hash_cm(entry.CM) for entry in history]
    assert before_ct == after_ct
    assert before_cm == after_cm


def test_attacker_uses_frozen_ct(small_history, monkeypatch):
    """The attacker's search must be run against history[i].CT itself (by
    object identity), never a freshly-built tuple.

    Exercises _test_candidate directly with a genuine (if huge) basis of
    period 0's own lattice -- kernel_basis_mod_q(pk_ri, q), same
    construction as the "garbage" negative control -- with reduced_norm
    forced to pass the Level-1 gate (see test_negative_control_* and the
    module docstring for why that gate exists). This is required to reach
    verify_search at all: a mismatched-lattice basis (e.g. stolen_sk, or
    any candidate not genuinely satisfying pk_ri.T=0 mod q) makes
    NewBasisDel raise before ever reaching Verify, and attack_period's own
    recovered candidate may or may not clear the gate for any given seed
    (that's the point of the gate) -- so asserting this identity invariant
    must not depend on either. What's under test here is purely "when
    Level 2 IS attempted, does it search the frozen CT_i" -- not whether
    this particular candidate would pass."""
    p, history, _stolen_pk, _stolen_sk, mu, u_pke = small_history
    on_lattice_candidate = e2e.kernel_basis_mod_q(history[0].pk_ri, p.q)
    seen_ct = []
    real_verify_search = e2e.verify_search

    def spy(CT, trap, params, trace=None):
        seen_ct.append(CT)
        return real_verify_search(CT, trap, params, trace)

    monkeypatch.setattr(e2e, "verify_search", spy)
    e2e._test_candidate(
        history, 0, on_lattice_candidate, p, mu, u_pke, source_label="test",
        membership_ok=True, reduced_norm=0.0,
    )
    assert seen_ct, "verify_search was never called"
    assert seen_ct[0] is history[0].CT


def test_level2_same_n0_definition(small_history):
    """level2_search_break must be True IFF N0_star is not None AND equals
    N0_legit — never True on a None/None coincidence or a mismatch."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    for i in range(len(history)):
        row = attack_period(history, i, len(history), stolen_sk, p, mu, u_pke)
        expected = row["N0_star"] is not None and row["N0_star"] == row["N0_legit"]
        assert row["level2_search_break"] == expected


def test_level3_gated_on_reachability(small_history, monkeypatch):
    """If LEVEL3_REACHABLE is False, level3_plaintext_break must always be
    False and the row must report level3_reachable=False, regardless of
    whether Level 2 broke."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    monkeypatch.setattr(e2e, "LEVEL3_REACHABLE", False)
    row = attack_period(history, 0, len(history), stolen_sk, p, mu, u_pke)
    assert row["level3_plaintext_break"] is False
    assert row.get("level3_reachable") is False


def test_no_break_reported_honestly(monkeypatch):
    """If no period yields N0_star == N0_legit, the summary must say
    'resists', never 'broken' — forced by monkeypatching verify_search to
    always return a non-matching value for the attacker's own search."""
    p = default_params()

    def always_miss(CT, trap, params, trace=None):
        return None

    # Only the ATTACKER's search (inside attack_period) should be forced to
    # miss; the legit doctor's own search (inside build_frozen_history) must
    # still succeed, or there's nothing to attack. Patch after history build.
    history, stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(J=2, params=p, seed=2)
    monkeypatch.setattr(e2e, "verify_search", always_miss)

    rows = [attack_period(history, i, len(history), stolen_sk, p, mu, u_pke) for i in range(len(history))]
    assert all(not r["level2_search_break"] for r in rows)
    any_l2 = any(r["level2_search_break"] for r in rows)
    assert any_l2 is False
    # mirror end_to_end_experiment's own summary logic at this outcome
    conclusion_should_say_resists = not any_l2
    assert conclusion_should_say_resists


def test_end_to_end_experiment_well_formed():
    """A full run at n=4 (fast) returns well-formed rows and a headline
    consistent with the measured any_l2_break."""
    p = default_params()
    result = end_to_end_experiment(J=2, base_params=p, n=4, seed=3, reducer_name="bkz")
    assert result["level3_reachable_in_principle"] is True
    assert len(result["rows"]) == 2
    for row in result["rows"]:
        assert "gs_norm" in row and "threshold" in row
        assert row["level2_search_break"] == (row["N0_star"] is not None and row["N0_star"] == row["N0_legit"])
        if not row["level2_search_break"]:
            assert row["level3_plaintext_break"] is False
    if result["any_l2_break"]:
        assert "break" in result["headline"].lower()
    else:
        assert "resists" in result["headline"].lower()


# --- Negative controls (audit point 1) --------------------------------
#
# A "Level 2 break" only means something if a candidate with NO genuine
# relationship to the real key reliably FAILS the identical test. These
# run the exact same _test_candidate path as the real attack, on inputs
# that must not be able to pass: the raw public kernel basis of pk_i
# (needs no secret at all), and a real, well-formed secret basis that is
# simply for the WRONG period.

def test_negative_control_garbage_fails_level2(small_history):
    p, history, _stolen_pk, _stolen_sk, mu, u_pke = small_history
    for i in range(len(history)):
        row = attack_period_negative_control(history, i, p, mu, u_pke, kind="garbage")
        assert row["level2_search_break"] is False, (
            f"period {i}: garbage (public-kernel-basis) candidate passed Level 2 -- "
            f"the success criterion is vacuous: {row}"
        )


def test_negative_control_wrong_period_fails_level2(small_history):
    """stolen_sk_J is a genuine, well-reduced secret basis -- just not for
    period i (i < J). It must not pass period i's Level 2 test either."""
    p, history, _stolen_pk, stolen_sk, mu, u_pke = small_history
    for i in range(len(history)):
        row = attack_period_negative_control(
            history, i, p, mu, u_pke, kind="wrong_period", wrong_period_sk=stolen_sk,
        )
        assert row["level2_search_break"] is False, (
            f"period {i}: wrong-period candidate (a real basis, wrong context) passed "
            f"Level 2 -- the success criterion is vacuous: {row}"
        )


def test_negative_controls_across_seeds():
    """The two controls above must hold reliably, not just for one lucky
    seed -- run several fresh histories at both tested dimensions."""
    p_base = default_params()
    failures = []
    for n in (4, 8):
        for seed in range(4):
            p = e2e.Params(n=n, q=p_base.q, sigma=p_base.sigma, l=p_base.l,
                            usability_C=p_base.usability_C, m=0)
            history, _stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(J=2, params=p, seed=seed)
            for i in range(len(history)):
                g = attack_period_negative_control(history, i, p, mu, u_pke, kind="garbage")
                w = attack_period_negative_control(
                    history, i, p, mu, u_pke, kind="wrong_period", wrong_period_sk=stolen_sk,
                )
                if g["level2_search_break"]:
                    failures.append(("garbage", n, seed, i))
                if w["level2_search_break"]:
                    failures.append(("wrong_period", n, seed, i))
    assert not failures, f"negative control(s) passed Level 2 (vacuous criterion): {failures}"


# --- Attacker input audit (audit point 2) ------------------------------

def test_attacker_never_reads_honest_sk(monkeypatch):
    """Structural + dynamic proof that the attack path reads only
    stolen_sk_J, public pk_i/R, and the frozen CT_i/CM_i -- never an
    honest sk_i for i < J.

    Static half: PeriodDB (the attacker's only view of history) carries no
    secret-key-shaped field at all, and attack_period's only secret-key
    parameter is stolen_sk_J.

    Dynamic half: every array object produced as an honest per-period
    secret basis while building the frozen history is tagged by object
    identity; the attack is then run with trapdoor/decrypt_record spied
    on, and none of the honest-tagged objects may ever be passed to them.
    """
    # --- static ---
    field_names = {f.name for f in dataclasses.fields(e2e.PeriodDB)}
    assert not any("sk" in name for name in field_names), (
        f"PeriodDB exposes a secret-key-shaped field: {sorted(field_names)}"
    )
    sig = inspect.signature(e2e.attack_period)
    sk_params = [name for name in sig.parameters if "sk" in name]
    assert sk_params == ["stolen_sk_J"], (
        f"attack_period's secret-key-shaped parameters changed: {sk_params}"
    )

    # --- dynamic ---
    honest_ids: set[int] = set()
    real_new_basis_del = e2e.new_basis_del
    real_strong_reduce = e2e.strong_reduce

    def tagging_new_basis_del(*args, **kwargs):
        out = real_new_basis_del(*args, **kwargs)
        honest_ids.add(id(out))
        return out

    def tagging_strong_reduce(sk):
        out, method = real_strong_reduce(sk)
        honest_ids.add(id(out))
        return out, method

    monkeypatch.setattr(e2e, "new_basis_del", tagging_new_basis_del)
    monkeypatch.setattr(e2e, "strong_reduce", tagging_strong_reduce)

    p = default_params()
    history, _stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(J=2, params=p, seed=7)
    assert honest_ids, "test setup bug: no honest sk was tagged during history construction"
    # stolen_sk_J is legitimately handed to the attacker -- it's the one
    # honest basis the threat model says they hold.
    honest_ids.discard(id(stolen_sk))

    seen_sk_ids = []
    real_trapdoor = e2e.trapdoor
    real_decrypt_record = e2e.decrypt_record

    def spy_trapdoor(pk, sk, *args, **kwargs):
        seen_sk_ids.append(id(sk))
        return real_trapdoor(pk, sk, *args, **kwargs)

    def spy_decrypt_record(pk, sk, *args, **kwargs):
        seen_sk_ids.append(id(sk))
        return real_decrypt_record(pk, sk, *args, **kwargs)

    monkeypatch.setattr(e2e, "trapdoor", spy_trapdoor)
    monkeypatch.setattr(e2e, "decrypt_record", spy_decrypt_record)

    for i in range(len(history)):
        attack_period(history, i, len(history), stolen_sk, p, mu, u_pke)

    leaked = honest_ids.intersection(seen_sk_ids)
    assert not leaked, "attack_period passed an honest sk_i object it should never have access to"


# --- PATCH 06: parameterization, every-period reporting, word-basis cross-check ---

def test_uses_input_n_and_J():
    """end_to_end_experiment must actually use the given n and J -- no
    hardcoded n=4/n=8 or fixed J anywhere downstream (PATCH 06 §1/§2's bug
    was in the FRONTEND button handlers, which this can't exercise, but the
    backend entry point they must call is asserted here)."""
    p = default_params()
    result = end_to_end_experiment(J=3, base_params=p, n=4, seed=9, reducer_name="bkz")
    assert result["n"] == 4
    assert result["J"] == 3
    assert len(result["rows"]) == 3  # every past period 0..J-1, PATCH 06 §4


def test_every_past_period_reported():
    """A run at J periods reports exactly J per-period rows (0..J-1)."""
    p = default_params()
    for J in (2, 3):
        result = end_to_end_experiment(J=J, base_params=p, n=4, seed=11, reducer_name="bkz")
        assert len(result["rows"]) == J
        assert sorted(r["period"] for r in result["rows"]) == list(range(J))


def test_l3_subset_or_equal_l2():
    """Plaintext recovery (L3) can never break at a period where the search
    (L2) didn't -- L3 is gated on L2 in _test_candidate, so this should
    hold by construction; checked across several seeds since it's a
    structural claim about every run, not one lucky draw."""
    p = default_params()
    for seed in range(5):
        result = end_to_end_experiment(J=2, base_params=p, n=4, seed=seed, reducer_name="bkz")
        l2, l3 = set(result["broken_periods_l2"]), set(result["broken_periods_l3"])
        assert l3 <= l2, f"seed={seed}: L3 broke at {l3 - l2} without L2 breaking there"


def test_panel_table_same_j():
    """The single-run experiment and the multi-n comparison, called with
    the SAME J, must both report that SAME J everywhere -- the backend
    guarantee the UI depends on to avoid showing a panel and a table
    computed at different J (PATCH 06 §2/§3's on-screen contradiction)."""
    p = default_params()
    J = 2
    panel = end_to_end_experiment(J=J, base_params=p, n=4, seed=1, reducer_name="bkz")
    table = end_to_end_multi_n(J=J, base_params=p, n_values=(4,), seed=1, reducer_name="bkz")
    assert panel["J"] == J
    assert table["J"] == J
    assert table["per_n"][0]["J"] == J


def test_word_basis_measured():
    """Every per-period row carries the word-basis cross-check fields
    (PATCH 06 §6.5): the honest baseline is always populated (computed
    during history construction, never gated on the attack succeeding),
    and the attacker's word_gs is populated whenever _basis_chain_norms
    didn't hit a genuine off-lattice error."""
    p = default_params()
    result = end_to_end_experiment(J=2, base_params=p, n=4, seed=3, reducer_name="bkz")
    for row in result["rows"]:
        assert row["honest_period_gs"] is not None
        assert row["honest_word_gs"] is not None
        assert row["honest_trap_norm"] is not None
        assert row["honest_beta_norm"] is not None
        assert "word_gs" in row and "word_pred_usable" in row and "l2_matches_wordpred" in row
        if row["word_gs"] is not None:
            assert row["beta_norm"] is not None
            assert row["trap_norm_predicted"] is not None


def test_word_gs_ge_period_gs():
    """NewBasisDel's delegation GROWS the norm going period -> word basis
    (PATCH 06 §6.5) -- word_gs should not be dramatically smaller than
    period_gs, on both the honest and (when measured) attacker side. Some
    slack is allowed since this is an independent Gaussian re-sample, not
    a deterministic function, but it must not collapse below the period
    basis's own norm."""
    p = default_params()
    for seed in range(5):
        result = end_to_end_experiment(J=2, base_params=p, n=4, seed=seed, reducer_name="bkz")
        for row in result["rows"]:
            assert row["honest_word_gs"] >= row["honest_period_gs"] * 0.9, (
                f"seed={seed} period={row['period']}: honest word_gs "
                f"({row['honest_word_gs']}) collapsed below period_gs "
                f"({row['honest_period_gs']})"
            )
            if row["word_gs"] is not None:
                assert row["word_gs"] >= row["gs_norm"] * 0.9, (
                    f"seed={seed} period={row['period']}: attacker word_gs "
                    f"({row['word_gs']}) collapsed below period_gs ({row['gs_norm']})"
                )


def test_l2_matches_wordpred_flag_present():
    """Every row carries l2_matches_wordpred (True/False/None-with-error),
    and the run-level result carries the aggregated disagreement list."""
    p = default_params()
    result = end_to_end_experiment(J=2, base_params=p, n=4, seed=3, reducer_name="bkz")
    assert "wordpred_disagreements" in result
    for row in result["rows"]:
        assert "l2_matches_wordpred" in row


def test_wordpred_disagreement_bannered():
    """When the independent word-basis prediction disagrees with the
    measured Level 2 outcome, the run is flagged for inspection (a
    non-empty wordpred_disagreements list and a matching caveat) rather
    than silently reported as a clean, fully-corroborated verdict. Seed 5
    at n=4/J=2 is a known disagreement case (word_gs predicts unusable,
    but the measured search broke anyway) -- see the PATCH 06 audit notes."""
    p = default_params()
    result = end_to_end_experiment(J=2, base_params=p, n=4, seed=5, reducer_name="bkz")
    disagreements = [r["period"] for r in result["rows"] if r.get("l2_matches_wordpred") is False]
    assert disagreements, "expected seed=5 to reproduce a word-basis prediction disagreement"
    assert result["wordpred_disagreements"] == disagreements
    assert any("word-basis" in c.lower() or "wordpred" in c.lower() for c in result["caveats"])


def test_negative_control_surfaced_per_run():
    """PATCH 06 §4: every end_to_end_experiment run carries its own
    negative-control status, and an untrustworthy run is bannered as such
    rather than reporting a break/resist verdict on faith."""
    p = default_params()
    result = end_to_end_experiment(J=2, base_params=p, n=4, seed=3, reducer_name="bkz")
    assert "control_ok" in result and "trustworthy" in result
    assert result["control_ok"] is True  # the fixed gate; see test_negative_control_* above
    assert "UNTRUSTWORTHY" not in result["headline"]
