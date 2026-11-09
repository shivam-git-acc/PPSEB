"""A cheap shape check on PPSEB keyword ciphertexts (index mode A′).

Deck finding 5: `verify` accepts any `(CT1, CT2)`, so `CT2 = 0` with
`CT1 = ⌊q/2⌋·1` matches every trapdoor. The deck's own proposed fix is a ZK
proof of well-formedness; it also names "reject CT₂ = 0" as a cheap stopgap.
This module is that stopgap, applied where the deck puts it: on submission,
before an entry is accepted into the index.

What the check uses
-------------------
An honest `CT2 = (pk·β⁻¹)ᵀ·B + e₂ (mod q)` with `B` uniform is, column by
column, statistically close to a uniform vector in `Z_q^m`. A uniform entry,
taken as its centred representative in `(-q/2, q/2]`, has root-mean-square
about `q/√12 ≈ 0.289·q`. A column whose RMS is far below that is not an honest
ciphertext column. The threshold is `q/8`, leaving a wide margin for honest
ciphertexts (measured, not assumed: see `measure_false_rejects`).

What it does not do
-------------------
It is a necessary condition, not a proof of well-formedness. It cannot tell an
honest uniform-looking column from a dishonest uniform-looking one, so it does
not close finding 5 for a public, open-submission ledger. The claim it supports
is narrow: the paper's canonical forgery and every forgery with a short `CT2`
column are rejected. `ppseb/` is not modified (Requirement 8.1).
"""

from __future__ import annotations

import random
from dataclasses import dataclass

import numpy as np

from ppseb.params import Params
from ppseb.scheme import peks_encrypt

#: Reject a CT2 column whose centred RMS falls below q / RMS_DIVISOR.
RMS_DIVISOR = 8


@dataclass(frozen=True)
class ShapeVerdict:
    ok: bool
    reason: str
    min_column_rms: float
    threshold_rms: float
    uniform_rms: float

    def as_dict(self) -> dict:
        return {"ok": self.ok, "reason": self.reason,
                "min_column_rms": round(self.min_column_rms, 3),
                "threshold_rms": round(self.threshold_rms, 3),
                "uniform_rms": round(self.uniform_rms, 3)}


def centred(values: np.ndarray, q: int) -> np.ndarray:
    """Representatives in (-q/2, q/2]."""
    v = np.mod(values, q)
    return np.where(v > q // 2, v - q, v)


def check_ciphertext_shape(ct1: np.ndarray, ct2: np.ndarray, params: Params) -> ShapeVerdict:
    """Accept only ciphertexts whose shape and CT2 columns look honest."""
    q, m, l = params.q, params.m, params.l
    uniform_rms = q / np.sqrt(12.0)
    threshold = q / RMS_DIVISOR
    if ct1.shape != (l,) or ct2.shape != (m, l):
        return ShapeVerdict(False, "wrong_shape", 0.0, threshold, uniform_rms)
    rms = np.sqrt(np.mean(centred(ct2, q).astype(np.float64) ** 2, axis=0))
    worst = float(rms.min())
    if worst < threshold:
        return ShapeVerdict(False, "short_ct2_column", worst, threshold, uniform_rms)
    return ShapeVerdict(True, "plausible", worst, threshold, uniform_rms)


def measure_false_rejects(params: Params, pk: np.ndarray, mu: np.ndarray, *,
                          samples: int = 1000, seed: int = 0,
                          keywords: tuple[str, ...] = ("diabetes", "asthma", "hiv",
                                                       "hypertension", "epilepsy")) -> dict:
    """How often does the check refuse an honest PEKS ciphertext?"""
    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)
    rejected, worst = 0, float("inf")
    for i in range(samples):
        ct = peks_encrypt(pk, keywords[i % len(keywords)], 0, mu, params, rng, pyrng)
        verdict = check_ciphertext_shape(ct["CT1"], ct["CT2"], params)
        worst = min(worst, verdict.min_column_rms)
        rejected += not verdict.ok
    return {"samples": samples, "false_rejects": rejected,
            "false_reject_rate": rejected / samples,
            "lowest_honest_column_rms": round(worst, 3),
            "threshold_rms": round(params.q / RMS_DIVISOR, 3),
            "uniform_rms": round(params.q / np.sqrt(12.0), 3),
            "params": {"n": params.n, "q": params.q, "m": params.m, "l": params.l}}
