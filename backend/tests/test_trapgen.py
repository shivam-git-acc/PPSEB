import numpy as np

from ppseb.params import default_params
from ppseb.trapgen import trapgen
from ppseb.trace import Trace


def test_trapgen_produces_valid_trapdoor():
    p = default_params()
    rng = np.random.default_rng(42)
    trace = Trace()
    A, T = trapgen(p, rng, trace)
    assert A.shape == (p.n, p.m)
    assert T.shape == (p.m, p.m)
    assert np.all((A @ T) % p.q == 0)
    assert len(trace.events) > 0
    assert any(e["type"] == "decision" for e in trace.events)
