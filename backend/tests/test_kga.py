import random

import numpy as np

from ppseb.params import default_params
from ppseb.scheme import initialization, trapdoor
from attacks.kga import kga_attack

DICTIONARY = ["flu", "asthma", "diabetes", "hypertension", "migraine", "eczema"]


def test_kga_recovers_secret_keyword():
    p = default_params()
    rng = np.random.default_rng(7)
    pyrng = random.Random(7)
    state = initialization(p, rng)
    pk0, sk0, mu = state["pk_r0"], state["sk_r0"], state["mu"]

    secret = "diabetes"
    trap = trapdoor(pk0, sk0, secret, 0, mu, p, pyrng)

    result = kga_attack(pk0, mu, 0, trap, DICTIONARY, p, seed=7)
    assert result["recovered_keyword"] == secret


def test_kga_returns_none_when_not_in_dictionary():
    p = default_params()
    rng = np.random.default_rng(8)
    pyrng = random.Random(8)
    state = initialization(p, rng)
    pk0, sk0, mu = state["pk_r0"], state["sk_r0"], state["mu"]

    secret = "gout"  # not in DICTIONARY
    trap = trapdoor(pk0, sk0, secret, 0, mu, p, pyrng)

    result = kga_attack(pk0, mu, 0, trap, DICTIONARY, p, seed=8)
    assert result["recovered_keyword"] is None
