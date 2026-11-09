"""Index mode A′: the cheap CT2 shape check (deck finding 5's stopgap).

The claims under test are deliberately narrow: the paper's canonical forgery is
refused on write, short CT2 columns are refused, honest ciphertexts are not, and
`ppseb/` itself is untouched. Nothing here claims the check proves
well-formedness — the module docstring says why it cannot.
"""

from __future__ import annotations

import numpy as np
import pytest

from medvault.harness import run_plant
from medvault.wellformed import check_ciphertext_shape, measure_false_rejects
from ppseb.params import default_params
from ppseb.scheme import initialization


@pytest.fixture(scope="module")
def keys():
    params = default_params()
    state = initialization(params, np.random.default_rng(7))
    return params, state["pk_r0"], state["mu"]


def test_canonical_forgery_is_refused_on_write_in_mode_a_prime():
    baseline = run_plant("A")
    assert baseline["accepted"] is True and baseline["appears_in_search"] is True

    checked = run_plant("A′")
    assert checked["mode"] == "A′"
    assert checked["accepted"] is False
    assert checked["reason"] == "malformed_ciphertext"
    assert checked["appears_in_search"] is False
    # The honest record still went through the same check and is searchable.
    assert checked["honest_entries_indexed"] >= 1
    assert "rec-001" in checked["record_ids"]


def test_zero_and_short_ct2_columns_are_rejected(keys):
    params, _pk, _mu = keys
    ct1 = np.full((params.l,), params.q // 2, dtype=np.int64)
    zero = np.zeros((params.m, params.l), dtype=np.int64)
    small = np.random.default_rng(1).integers(-1, 2, size=(params.m, params.l))
    one_bad_column = np.random.default_rng(2).integers(0, params.q, size=(params.m, params.l))
    one_bad_column[:, 3] = 0
    for ct2 in (zero, small % params.q, one_bad_column):
        verdict = check_ciphertext_shape(ct1, ct2, params)
        assert verdict.ok is False and verdict.reason == "short_ct2_column"


def test_wrong_shapes_are_rejected(keys):
    params, _pk, _mu = keys
    ct1 = np.zeros((params.l,), dtype=np.int64)
    ct2 = np.zeros((params.m - 1, params.l), dtype=np.int64)
    assert check_ciphertext_shape(ct1, ct2, params).reason == "wrong_shape"


def test_honest_ciphertexts_pass(keys):
    """Measured, not assumed. The full 1 000-sample figure is in repro.json."""
    params, pk, mu = keys
    report = measure_false_rejects(params, pk, mu, samples=200, seed=11)
    assert report["false_rejects"] == 0
    # The margin is wide: the lowest honest column sits well above the threshold.
    assert report["lowest_honest_column_rms"] > 1.5 * report["threshold_rms"]


def test_ppseb_verify_is_unchanged():
    """Requirement 8.1: the check lives in medvault/, not in ppseb/."""
    import inspect

    import ppseb.scheme as scheme
    assert "check_ciphertext_shape" not in inspect.getsource(scheme)
