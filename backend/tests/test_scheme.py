import random

import numpy as np

from ppseb.params import default_params
from ppseb.scheme import (
    initialization, keyext, peks_encrypt, trapdoor, verify,
    encrypt_record, decrypt_record,
)
from ppseb.trace import Trace


def _setup(seed=0):
    p = default_params()
    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)
    trace = Trace()
    state = initialization(p, rng, trace)
    return p, rng, pyrng, trace, state


def test_matching_keyword_verifies():
    p, rng, pyrng, trace, state = _setup(1)
    pk0, sk0, mu = state["pk_r0"], state["sk_r0"], state["mu"]
    ct = peks_encrypt(pk0, "diabetes", 0, mu, p, rng, pyrng, trace)
    trap = trapdoor(pk0, sk0, "diabetes", 0, mu, p, pyrng, trace)
    match, y = verify(ct["CT1"], ct["CT2"], trap, p, trace)
    assert match is True


def test_nonmatching_keyword_rejects():
    p, rng, pyrng, trace, state = _setup(2)
    pk0, sk0, mu = state["pk_r0"], state["sk_r0"], state["mu"]
    ct = peks_encrypt(pk0, "diabetes", 0, mu, p, rng, pyrng, trace)
    trap = trapdoor(pk0, sk0, "hypertension", 0, mu, p, pyrng, trace)
    match, y = verify(ct["CT1"], ct["CT2"], trap, p, trace)
    assert match is False


def test_keyext_chain_and_search_at_later_period():
    p, rng, pyrng, trace, state = _setup(3)
    pk, sk, mu = state["pk_r0"], state["sk_r0"], state["mu"]
    for j in range(1, 4):
        pk, sk = keyext(j, pk, sk, p, pyrng, trace)
    ct = peks_encrypt(pk, "asthma", 3, mu, p, rng, pyrng, trace)
    trap = trapdoor(pk, sk, "asthma", 3, mu, p, pyrng, trace)
    match, _ = verify(ct["CT1"], ct["CT2"], trap, p, trace)
    assert match is True


def test_encrypt_decrypt_record_roundtrip():
    p, rng, pyrng, trace, state = _setup(4)
    pk0, sk0, u_pke = state["pk_r0"], state["sk_r0"], state["u_pke"]
    record = b"Patient: J. Doe, Dx: diabetes"
    ct = encrypt_record(pk0, record, u_pke, p, rng, pyrng, trace)
    out = decrypt_record(pk0, sk0, ct, u_pke, p, pyrng, trace)
    assert out == record


def test_correctness_failure_rate_is_low():
    """Sweep several random keyword/keypair draws; matching should verify
    and non-matching should reject with a low failure rate."""
    p = default_params()
    fails = 0
    trials = 15
    for seed in range(trials):
        rng = np.random.default_rng(100 + seed)
        pyrng = random.Random(100 + seed)
        state = initialization(p, rng)
        pk0, sk0, mu = state["pk_r0"], state["sk_r0"], state["mu"]
        ct = peks_encrypt(pk0, "diabetes", 0, mu, p, rng, pyrng)
        trap_match = trapdoor(pk0, sk0, "diabetes", 0, mu, p, pyrng)
        m1, _ = verify(ct["CT1"], ct["CT2"], trap_match, p)
        trap_mismatch = trapdoor(pk0, sk0, "flu", 0, mu, p, pyrng)
        m2, _ = verify(ct["CT1"], ct["CT2"], trap_mismatch, p)
        if not m1:
            fails += 1
        if m2:
            fails += 1
    failure_rate = fails / (2 * trials)
    assert failure_rate < 0.1, f"correctness failure rate too high: {failure_rate}"
