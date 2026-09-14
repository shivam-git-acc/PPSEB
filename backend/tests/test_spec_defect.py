import numpy as np

from ppseb.params import default_params
from attacks.spec_defect import run_paper_version, run_corrected_version


def test_paper_version_is_not_executable():
    p = default_params()
    rng = np.random.default_rng(0)
    from ppseb.trapgen import trapgen
    pk0, sk0 = trapgen(p, rng)
    result = run_paper_version(1, pk0, sk0, p)
    assert result["success"] is False
    assert "line_6" in result["failures"]
    assert "line_7" in result["failures"]
    assert result["failures"]["line_6"]["type"] in ("UnboundLocalError", "NameError")
    assert result["failures"]["line_7"]["type"] in ("UnboundLocalError", "NameError")


def test_corrected_version_produces_valid_chain():
    p = default_params()
    result = run_corrected_version(J=3, params=p, seed=1)
    assert result["success"] is True
    assert len(result["chain"]) == 4
    assert all(entry["valid"] for entry in result["chain"])
