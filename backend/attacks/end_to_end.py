"""Finding 2 — end-to-end forward-security attack (PATCH 05).

PATCH 01-04 established a NORM PROXY: is the attacker's recovered candidate
short enough (by an audited threshold) to plausibly be a usable trapdoor?
This module upgrades that proxy to a FUNCTIONAL demonstration: build the
honest doctor's actual searchable database at each period, FREEZE it,
evolve the key forward to period J (where it gets stolen), then let the
attacker — holding only the stolen SK_r|J and public data — reconstruct
SK*_r|i for an earlier period i and run the SAME search (and decrypt) code
path the real doctor would have used, against the FROZEN ciphertexts.

**Critical honesty rule:** the attacker NEVER regenerates CT_i or CM_i using
the recovered key — that would be circular (of course a fresh trapdoor
matches a fresh ciphertext) and would prove nothing about forward security.
Each PeriodDB is frozen at creation (`@dataclass(frozen=True)`) and
`attack_period` asserts its content hash is unchanged before returning.

## §0 — what does the paper's Decrypt actually need? (blocking sub-task)

From the paper (§4.3): `(N, W, I_M) <- PPSEB.Encrypt(M, pk_r||j)` takes only
the PUBLIC key, and `M0 <- PPSEB.Decrypt(CM0, j, SK_r||j)` takes only the
period secret key and nothing separately patient-side. Our implementation
(`ppseb.scheme.encrypt_record` / `decrypt_record`) matches this exactly —
`encrypt_record` takes `pk_rj` (+ the public anchor `u_pke`), `decrypt_record`
takes `sk_rj` (+ the same public `u_pke`) and nothing else secret. Since
Decrypt needs nothing but the period secret key, a recovered SK*_r|i that is
short enough MAY also decrypt the old record — Level 3 is reachable IN
PRINCIPLE, gated only on whether the recovered basis clears the record
decode bound (measured below, never assumed).

## Three levels, per period, per run

- **Level 1 (norm proxy):** gs_norm(SK*_r|i) <= the audited usability
  threshold (PATCH 02 §A.2). Necessary but not sufficient.
- **Level 2 (THE forward-security functionality break):** a trapdoor built
  from SK*_r|i, run against the FROZEN CT_i, returns the SAME sequence
  number N0 the legitimate doctor got when they searched at period i. This
  is the headline pass/fail.
- **Level 3 (confidentiality break):** decrypting the FROZEN CM_i entry at
  that N0 with SK*_r|i recovers the SAME plaintext the doctor encrypted.

Verdicts are per period, per level, derived from measured N0/plaintext
comparisons — never averaged or cherry-picked, and never assumed from the
norm alone.

**A dimension constraint discovered while wiring this up:** this is the
first patch to actually RUN H2 (patches 01-04 only ever measured norms, so
H2's own construction never mattered) — and H2's low-norm twisted-binomial
construction (`hashes._irreducible_twist`, x^n - c) only exists for n whose
every prime factor divides q-1 (Lidl-Niederreiter's binomial irreducibility
criterion). For the default q=257, q-1=256=2^8, so this holds only for n a
power of 2. PATCH 04's own n=6 is therefore NOT usable here — not a search
failure, a genuine non-existence — so this module compares n=4 against n=8
instead (both powers of 2), documented rather than silently swapped.

**Reconciling with PATCH 04's "resists_symmetric_bkz" (n=4/n=6, norm proxy
only):** `three_way_reduction_sweep` never tested n=8 at all (its own
`DEFAULT_THREE_WAY_N_VALUES = (4, 6)`, bounded by measured BKZ cost at
n=8), so there is no shared n between the two patches' fair-BKZ runs
except n=4 — "n=6 held" says nothing directly about n=8. Before the
NewBasisDel-laundering fix above, this module's own functional test
reported a break at EVERY tested n (4 AND 8, identically), which is now
understood to be the SAME vacuous-criterion bug PATCH 04 never hit
(PATCH 04 never calls Trapdoor/NewBasisDel at all — its "broken" verdict
is purely `reduced_norm <= threshold` on the RAW recovered candidate).
Post-fix, this module's own n=4 runs land on a small, seed-dependent,
genuine break confined to the period immediately before the theft (never
2 periods back, in every seed sampled), and n=8 has shown none in the
same sweep — consistent with PATCH 04's fair-BKZ norm-proxy picture
("mostly resists, at small dimensions") rather than contradicting it. The
apparent "n=6 held, n=8 broke" tension was the vacuous-criterion bug
wearing a dimension-shaped costume, not a real dimension effect.

**A second interaction discovered the same way:** PATCH 03's dimension-aware
sigma (needed for NewBasisDel's own correctness) makes Trap's own norm grow,
which — at the ORIGINAL fixed ciphertext-noise width — can blow Verify's
decode margin and break even the LEGITIMATE doctor's own search (never
visible before PATCH 05, which is the first patch to actually run PEKS/
Trapdoor/Verify rather than just measure norms).

**Two real, confirmed bugs this surfaced (audit-caught, not self-caught):**

1. The first fix attempted for the sigma/noise interaction above scaled
   `ciphertext_noise_sigma` DOWN in proportion to how far sigma was scaled
   up, preserving the original sigma*noise product. That made the
   legitimate doctor's search reliable again, but pushed the noise so
   small that discrete Gaussian samples are essentially always exactly 0
   — a symptom of the bug below, not yet its cause. Mitigated (not fixed
   on its own) by CALIBRATING `ciphertext_noise_sigma` per run against
   this run's own measured legitimate Trap norm (`TARGET_MARGIN_STD`),
   with a longer keyword test length (`END_TO_END_L`, up from the
   scheme's default l=10) to sharpen the all-slots-must-pass
   discrimination. This keeps the legitimate doctor's margin comparable
   across dimensions, but does NOT by itself fix vacuousness — see (2).

2. **The actual root cause, found only by running the mandated negative
   control:** even with (1) in place, a candidate with NO relationship to
   the real key at all — the raw, unreduced kernel basis of pk_r|i,
   computable by ANYONE from the public key alone, no theft needed —
   still passed Level 2 as often as a genuine recovered candidate,
   *including at n=4/n=8 with no forward-security chain involved at all*
   (confirmed directly against a fresh TrapGen root at default params:
   see the audit notes). The cause is in `ppseb.samplers.new_basis_del`,
   not in this module's noise tuning: its re-randomization step draws
   `resample_factor * m` fresh discrete-Gaussian candidates of a FIXED
   width `sigma` and greedily keeps the shortest independent set,
   regardless of how good or bad the caller's own input trapdoor was.
   NewBasisDel's own correctness precondition — sigma >=
   gs_norm(input_basis) * omega(sqrt(log m)) — is silently violated
   whenever the input is oversized (garbage) or off-lattice
   (wrong-period), and the implementation does not reject that; it just
   returns something, laundering an unusable input into an
   apparently-usable trapdoor. That precondition is EXACTLY Level 1's
   `usability_threshold` (PATCH 02 §A.2) and the lattice-`membership_ok`
   check already computed per candidate — they were being measured but
   never used to gate whether Level 2 was even attempted. Fixed in
   `_test_candidate`: Level 2 is now skipped (reported as no break, with
   `level2_skipped_reason` set) unless the candidate clears BOTH Level 1
   and lattice membership first. This is the "stricter match definition"
   forced by the audit — passing Level 2 now requires genuinely passing
   Level 1 too, not just an N0 coincidence.

Both negative controls (`attack_period_negative_control`, kind="garbage"
and kind="wrong_period") are exercised in tests/test_end_to_end.py and
must keep failing reliably (checked across multiple seeds and both tested
dimensions) for any Level 2/3 result here to mean anything. Post-fix,
n=4 shows a genuine (small, seed-dependent) Level 2 break confined to one
period back from the theft; n=8 shows none in the same sweep — a
dimension-dependent pattern consistent with the R^-1-recovered candidate's
norm growing faster than the threshold as m grows, not the artifact the
pre-fix code was reporting (which broke at EVERY tested dimension,
identically to the negative controls, because it wasn't measuring
anything real).

**Level 2 vs Level 3, checked honestly (audit point 4):** `decrypt_record`
always calls `sample_pre` fresh on the FROZEN `CM` entry (the same object,
by identity, from `history[i].CM` — never regenerated) using the
candidate `sk_star`; its decode bound is enforced by the same
noise-accumulation mechanism as Verify's (`<e, t0>` grows with the
recovered basis's own norm), not a magnitude check that could pass
vacuously. Because a record is ~40-50 bytes (320-400 independent decode
bits, all of which must be correct) versus Verify's l=30 slots, Level 3
is a strictly harder bar — confirmed empirically, not just by inspection:
a 32-seed sweep at n=4 found 14 Level 2 breaks, of which 3 broke Level 2
WITHOUT breaking Level 3 ("search recovered, plaintext did not"). If L2
and L3 were secretly the same test, that split could not happen.

## PATCH 06 — parameterization, every-period reporting, word-basis cross-check

Three independent fixes/additions on top of the above:

1. **Hardcoded n/J were a FRONTEND bug**, not a backend one: this module's
   `end_to_end_experiment`/`end_to_end_multi_n` already took `n` and `J` as
   real parameters; `ForwardSecTab.jsx`'s button handlers ignored them
   (`n: 4` literal, and the comparison table using a backend-default n
   list independent of the UI). Fixed in the frontend; documented here so
   the backend/frontend split of that bug is on record.
2. **Every past period is reported**, not a cherry-picked subset — `rows`
   always has exactly one entry per period `0..J-1` (unchanged behavior,
   confirmed by `test_every_past_period_reported`).
3. **The negative control now runs on EVERY call to `end_to_end_experiment`**
   (kind="garbage", every period), not just in the test suite — if it ever
   passes, the whole run is bannered `UNTRUSTWORTHY RUN` in the headline
   and `trustworthy`/`control_ok` are set to `False`, rather than reporting
   a break/resist verdict a viewer would have no way to distrust.
4. **Word-basis cross-check (§6.5):** `_basis_chain_norms` independently
   re-derives the WORD basis (`beta = H2(keyword, period)`, one more
   `NewBasisDel` delegation past the period basis) that `SamplePre`
   actually consumes, and predicts Level 2 success from `word_gs <=
   threshold` — a second, independent signal alongside the measured
   same-N0 outcome. Every row carries both the honest baseline
   (`honest_period_gs`/`honest_word_gs`/`honest_trap_norm`/
   `honest_beta_norm`, computed once during history construction) and the
   attacker's own (`word_gs`/`trap_norm_predicted`/`beta_norm`), plus
   `word_pred_usable` and `l2_matches_wordpred`. Disagreements are
   surfaced (`wordpred_disagreements` at the run level, plus a caveat) for
   inspection rather than silently trusted — since this is an
   INDEPENDENT re-sample (fresh Gaussian draws, not a trace of the actual
   Level 2 attempt), occasional disagreement reflects NewBasisDel's own
   sample-to-sample variance and is expected sometimes, not automatically
   proof of a new bug; a disagreement is a flag to inspect, not an
   automatic distrust verdict (that's reserved for the negative control).

## Post-PATCH-06 audit: drilling into a flagged (word-basis-disagreement) break

A viewer flagged exactly this kind of row (period near the compromise,
L2+L3 broken, word-basis prediction disagreeing) and asked whether it was
a small-database artifact -- with only a few records per period, a
degraded trapdoor could plausibly "match" the one obvious record by
coincidence rather than genuine keyword decoding. Investigated directly,
not assumed away:

- **Per-period negative controls, not just an aggregate line.** Both
  kind="garbage" and kind="wrong_period" now run at EVERY period on every
  `end_to_end_experiment` call (`row["control_garbage_passed"]`/
  `row["control_wrong_period_passed"]`), so a specific flagged period's
  break can be checked against controls run at that SAME period, not an
  aggregate that could be held elsewhere while this one is bad. Both held
  at the flagged period.
- **False-accept-rate test.** The exact recovered trapdoor from a flagged
  break was checked against 50 additional decoy keywords (the full
  expanded `DICTIONARY`, none of which were the target) it had never been
  tested against: 0/50 false accepts, and it correctly matched a FRESH
  re-encryption of the target keyword (not just the one frozen
  ciphertext). This is real, repeatable, keyword-specific discrimination
  -- not a coincidence of "matches whatever's first in a small DB".
- **RECORDS_PER_PERIOD raised from 4 to 20** (dictionary expanded from 8
  to 51 keywords to support it) as a standing strengthening rather than a
  one-off check -- every future run now tests discrimination against a
  much larger decoy pool by default, not just the diagnostic above.
  Re-verified clean against the full test suite (legit reliability,
  negative controls, word-basis checks) at the new value.
- **Conclusion on the specific flagged case:** the break was genuine, not
  an artifact -- but it IS fragile: the word-basis prediction disagreed
  because NewBasisDel's Klein-resampling has real run-to-run variance, so
  the SAME recovered period-basis candidate can yield either a working or
  a non-working word basis depending on the random draw. "Genuine but
  variance-dependent" is the honest characterization; concluding
  "survives" from the word-basis disagreement alone would have been
  wrong here, since the actual measured outcome (checked directly, not
  inferred from the independent proxy) was a real break.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

import numpy as np

from ppseb.hashes import H1, H1_inverse, H2, H2_inverse
from ppseb.linalg import centered_mod_q, gram_schmidt_norm, kernel_basis_mod_q, mat_mod_mixed
from ppseb.params import Params
from ppseb.samplers import new_basis_del, sample_pre
from ppseb.scheme import decrypt_record, encrypt_record, peks_encrypt, trapdoor, verify
from ppseb.trace import Trace
from ppseb.trapgen import trapgen

from .forward_sec import _lll_reducer, _recover_candidate, sigma_for_params, usability_threshold
from ppseb.linalg import strong_reduce

DICTIONARY = (
    "flu", "asthma", "diabetes", "hypertension", "migraine", "eczema",
    "bronchitis", "arthritis", "psoriasis", "gout", "anemia", "epilepsy",
    "glaucoma", "cirrhosis", "pancreatitis", "endometriosis", "scoliosis",
    "tinnitus", "vertigo", "shingles", "cellulitis", "lymphoma", "melanoma",
    "sciatica", "tendonitis", "conjunctivitis", "laryngitis", "sinusitis",
    "pneumonia", "tuberculosis", "hepatitis", "nephritis", "gastritis",
    "colitis", "dermatitis", "osteoporosis", "fibromyalgia", "narcolepsy",
    "hypothyroidism", "hyperthyroidism", "pericarditis", "endocarditis",
    "meningitis", "encephalitis", "bursitis", "myocarditis", "phlebitis",
    "urticaria", "rosacea", "otitis", "pharyngitis",
)
RECORDS_PER_PERIOD = 20
GROUND_TRUTH_IDX = 0

# n=6 (PATCH 04's own choice) has no valid H2 twist for q=257 — see the
# module docstring's dimension-constraint note. n=4 and n=8 are both powers
# of 2 (compatible with q-1=256) and span the same "does it survive a
# larger dimension" question PATCH 04's fairness sweep asked.
DEFAULT_END_TO_END_N_VALUES = (4, 8)

# Empirically calibrated (see build_frozen_history's audit note and PATCH 05
# ChatOps notes): l=10 (the scheme default) cannot simultaneously give the
# legitimate doctor a reliable pass AND reject a garbage/wrong-key trapdoor
# reliably — the two Trap-norm populations aren't separated enough relative
# to a 10-slot all-must-pass test. l=30 sharpens that discrimination.
# TARGET_MARGIN_STD is the per-coordinate noise standard deviation (in units
# of q) the calibration below aims for, relative to THIS RUN's own measured
# legitimate Trap norm — chosen (by the same empirical sweep) to keep the
# legitimate doctor's pass rate high while a garbage/wrong-key Trap (whose
# norm this codebase's NewBasisDel construction still measurably — if not
# hugely — inflates relative to a genuine recovery) fails reliably.
END_TO_END_L = 30
TARGET_MARGIN_STD = 34.0

LEVEL3_REACHABLE = True
LEVEL3_NOTE = (
    "Paper's own algorithm signatures (§4.3): Encrypt(M, pk_r||j) takes only the "
    "PUBLIC key; Decrypt(CM0, j, SK_r||j) takes only the period SECRET key and "
    "nothing separately patient-side. Our implementation (scheme.encrypt_record / "
    "decrypt_record) matches this exactly. Since Decrypt needs nothing but "
    "SK_r||j, a recovered SK*_r|i that is short enough MAY also decrypt the old "
    "record -- Level 3 is reachable IN PRINCIPLE, gated only on whether the "
    "recovered basis clears the record decode bound (measured below, not assumed)."
)


@dataclass(frozen=True)
class PeriodDB:
    """An IMMUTABLE snapshot of the honest doctor's searchable database at
    one period. Created once, forward, during build_frozen_history — never
    mutated afterward. `ct_hash`/`cm_hash` let a test (and attack_period
    itself) prove the attacker never regenerated these with a recovered key.
    """
    period: int
    pk_ri: np.ndarray
    records: tuple           # ((N, keyword, M_bytes), ...)
    CT: tuple                # ((N, CT1, CT2), ...)
    CM: tuple                # ((N, ciphertext_dict), ...)
    legit_trap_demo: dict    # {"keyword": w, "N0": N}
    R_into_next: np.ndarray  # public R used to evolve period -> period+1
    ct_hash: str
    cm_hash: str


def _hash_ct(CT: tuple) -> str:
    h = hashlib.sha256()
    for (N, ct1, ct2) in CT:
        h.update(int(N).to_bytes(8, "big", signed=True))
        h.update(np.ascontiguousarray(ct1).tobytes())
        h.update(np.ascontiguousarray(ct2).tobytes())
    return h.hexdigest()


def _hash_cm(CM: tuple) -> str:
    h = hashlib.sha256()
    for (N, ct) in CM:
        h.update(int(N).to_bytes(8, "big", signed=True))
        h.update(np.ascontiguousarray(ct["C1"]).tobytes())
        h.update(np.ascontiguousarray(ct["C2"]).tobytes())
    return h.hexdigest()


def _basis_chain_norms(
    pk_i: np.ndarray, sk_period: np.ndarray, keyword: str, period: int,
    mu: np.ndarray, params: Params, pyrng: random.Random,
) -> dict:
    """PATCH 06 §6.5 — instruments the FULL delegation chain a candidate
    basis actually goes through inside Trapdoor, which SamplePre does NOT
    consume the period basis for: it consumes a WORD basis one MORE
    NewBasisDel delegation downstream (beta = H2(keyword, period)). That
    delegation GROWS the norm, so a period basis under threshold can still
    yield an over-threshold word basis -- explaining any gap between
    Level 1 (period-norm proxy) and Level 2 (actual search).

    This recomputes new_basis_del/sample_pre INDEPENDENTLY of the real
    Trapdoor() call used for the actual Level 2 attempt (fresh Gaussian
    draws) -- by design (see the module docstring): it is a cross-check
    against an independent prediction, not a trace of the exact call.
    Raises (propagated to the caller) if sk_period isn't genuinely a basis
    of L_perp_q(pk_i) -- e.g. a wrong-period candidate -- since no word
    basis is well-defined to report in that case.
    """
    q = params.q
    beta = H2(keyword, period, params)
    beta_inv = H2_inverse(beta, q)
    beta_inv = np.array([[int(x) for x in row] for row in (beta_inv % q)], dtype=np.int64)
    sk_word = new_basis_del(pk_i, beta, sk_period, params.sigma, q, pyrng, R_inv=beta_inv)
    A_w = (pk_i @ beta_inv) % q
    trap = sample_pre(A_w, sk_word, mu, params.sigma, q, pyrng)
    return {
        "period_gs": gram_schmidt_norm(centered_mod_q(sk_period, q)),
        "word_gs": gram_schmidt_norm(centered_mod_q(sk_word, q)),
        "trap_norm": float(np.linalg.norm(trap.astype(float))),
        "beta_norm": gram_schmidt_norm(centered_mod_q(beta, q)),
    }


def verify_search(CT: tuple, trap: np.ndarray, params: Params, trace: Trace | None = None) -> int | None:
    """Runs PPSEB.Verify over every entry of a (frozen) CT tuple and returns
    the sequence number N of the matching one, or None. This is the SAME
    routine used for both the legitimate doctor's search and the attacker's
    — the only thing that ever differs between them is which trapdoor
    (built from sk vs sk_star) is passed in.
    """
    for (N, CT1, CT2) in CT:
        match, _y = verify(CT1, CT2, trap, params, trace)
        if match:
            return N
    return None


def build_frozen_history(
    J: int, params: Params, seed: int = 0, h1_variant: str = "low_norm",
    strengthen_legit: bool = True, dictionary: tuple[str, ...] = DICTIONARY,
    records_per_period: int = RECORDS_PER_PERIOD,
    trace: Trace | None = None, max_seed_retries: int = 4,
) -> tuple[list[PeriodDB], np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Thin retry wrapper around `_build_frozen_history_once`.

    The per-run noise calibration (module docstring's audit note) targets
    a margin that is reliable but not guaranteed: a rare noise draw can
    occasionally make even the LEGITIMATE doctor's own search fail (an
    `AssertionError` from `_build_frozen_history_once`). Letting that
    crash the whole experiment would be its own kind of dishonesty --
    treating a setup hiccup as if it were a finding. Instead, retry with
    seed+1, seed+2, ... (bounded by `max_seed_retries`); if every attempt
    fails, the original error still propagates. This never touches the
    ATTACKER's success criterion or which candidate gets tested -- it only
    ensures the experimental setup itself succeeded, the same way a real
    deployment would re-encrypt on a failed self-check rather than
    silently operating on an unusable database. Any retry is reported via
    `trace.note` so it stays visible, not silently absorbed.
    """
    last_error: AssertionError | None = None
    for attempt in range(max_seed_retries + 1):
        try:
            result = _build_frozen_history_once(
                J, params, seed=seed + attempt, h1_variant=h1_variant,
                strengthen_legit=strengthen_legit, dictionary=dictionary,
                records_per_period=records_per_period, trace=trace,
            )
            if attempt > 0 and trace is not None:
                trace.note(
                    f"Retried history construction ({attempt} retry(ies)) after a legit-search "
                    f"reliability failure",
                    detail="The calibrated noise margin is reliable but not guaranteed; this "
                           "run's original seed happened to draw noise that made the legitimate "
                           "doctor's OWN search fail. Retried with a different seed rather than "
                           "reporting a crash as a finding -- the attacker's candidate and success "
                           "criterion are untouched by this.",
                    data={"original_seed": seed, "used_seed": seed + attempt, "retries": attempt},
                    algo="EndToEnd",
                )
            return result
        except AssertionError as e:
            if "legit doctor must find its own record" not in str(e):
                raise
            last_error = e
    assert last_error is not None
    raise last_error


def _build_frozen_history_once(
    J: int, params: Params, seed: int = 0, h1_variant: str = "low_norm",
    strengthen_legit: bool = True, dictionary: tuple[str, ...] = DICTIONARY,
    records_per_period: int = RECORDS_PER_PERIOD,
    trace: Trace | None = None,
) -> tuple[list[PeriodDB], np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Builds and FREEZES the honest doctor's database at periods 0..J-1,
    evolving the key forward one more time past period J-1 to reach the
    "current, now-compromised" period J. Returns
    (history, stolen_pk_J, stolen_sk_J, mu, u_pke).

    Mutates `params.sigma` in place to a dimension-aware value (PATCH 03
    Lever 1) before anything else is built, exactly like scaling_sweep —
    otherwise a fixed sigma could make even the honest side unusable and
    the whole comparison would be meaningless.
    """
    q = params.q
    rng = np.random.default_rng(seed)
    pyrng = random.Random(seed)

    pk0, sk0 = trapgen(params, rng, trace)
    params.sigma = sigma_for_params(sk0, params)
    if strengthen_legit:
        sk0, _method = strong_reduce(sk0)
        assert bool(np.all(mat_mod_mixed(pk0, sk0, q) == 0)), "strong_reduce left L_perp_q(pk0)"

    mu = rng.integers(0, q, size=params.n).astype(np.int64)
    u_pke = rng.integers(0, q, size=params.n).astype(np.int64)

    # PATCH 05 audit finding (a real, confirmed bug — see the module
    # docstring): an earlier version of this function "fixed" the
    # legitimate doctor's own search failing (caused by PATCH 03's
    # dimension-aware sigma inflating Trap's norm) by scaling
    # ciphertext_noise_sigma DOWN in proportion to sigma. That was wrong in
    # a way a negative control caught immediately: the noise became so
    # small that the discrete Gaussian samples are essentially always
    # exactly 0, so Verify degenerates into a NOISELESS exact-equality
    # check that ANY algebraically-valid trapdoor passes — including one
    # built from a totally unrelated, secret-free, public basis (the raw
    # kernel basis of pk_i, computable by anyone). The success criterion
    # was vacuous: it was measuring "is there SOME valid trapdoor for this
    # keyword" (always true) rather than "does THIS SPECIFIC recovered key
    # work" (the only question that says anything about forward security).
    #
    # Fixed by CALIBRATING the noise to the actual measured Trap norm this
    # run produces, targeting a per-coordinate margin (TARGET_MARGIN_STD)
    # empirically chosen (see PATCH 05 audit notes) to be small enough that
    # the legitimate doctor passes reliably, yet — combined with a longer
    # keyword test length (END_TO_END_L, up from the default l=10, which
    # sharpens the all-l-coordinates-must-pass discrimination) — large
    # enough relative to a garbage/wrong-key Trap's much larger norm that
    # it reliably fails. This is verified BY TEST (test_negative_control_*
    # in tests/test_end_to_end.py), not assumed from the calibration alone.
    params.l = END_TO_END_L
    calib_trap = trapdoor(pk0, sk0, "__e2e_calibration__", 0, mu, params, pyrng)
    calib_norm = float(np.linalg.norm(calib_trap.astype(float)))
    params.ciphertext_noise_sigma = TARGET_MARGIN_STD / calib_norm
    if trace is not None:
        trace.note(
            "Calibrated ciphertext noise to the measured legitimate Trap norm",
            detail="A fixed or proportionally-scaled noise width made Verify noiseless "
                   "(and hence unable to distinguish a real recovered key from public "
                   "garbage) once sigma grew with dimension — see the module docstring. "
                   "Calibrating against THIS run's actual Trap norm keeps the legitimate "
                   "doctor's margin comparable across n, and is checked (not assumed) by "
                   "the negative-control tests.",
            data={"calibration_trap_norm": calib_norm, "target_margin_std": TARGET_MARGIN_STD,
                  "resulting_ciphertext_noise_sigma": params.ciphertext_noise_sigma, "l": params.l},
            algo="EndToEnd",
            highlight=True,
        )

    history: list[PeriodDB] = []
    pk, sk = pk0, sk0
    for i in range(J):
        kws = pyrng.sample(list(dictionary), min(records_per_period, len(dictionary)))
        records = tuple(
            (n_id, kw, f"Patient record #{n_id} at period {i}: dx={kw}".encode())
            for n_id, kw in enumerate(kws)
        )

        ct_entries = []
        for n_id, kw, _M in records:
            ct = peks_encrypt(pk, kw, i, mu, params, rng, pyrng, trace)
            ct_entries.append((n_id, ct["CT1"], ct["CT2"]))
        CT = tuple(ct_entries)

        cm_entries = []
        for n_id, _kw, M in records:
            cm_entries.append((n_id, encrypt_record(pk, M, u_pke, params, rng, pyrng, trace)))
        CM = tuple(cm_entries)

        target_id, target_kw, _target_M = records[GROUND_TRUTH_IDX]
        legit_trap = trapdoor(pk, sk, target_kw, i, mu, params, pyrng, trace)
        N0_legit = verify_search(CT, legit_trap, params, trace)
        assert N0_legit is not None, f"legit doctor must find its own record at period {i}"

        # PATCH 06 §6.5 -- honest baseline for the period/word/trap norm
        # cross-check. Computed here (while `sk` is still in scope) because
        # PeriodDB deliberately carries no secret key; only the resulting
        # NUMBERS are kept, for reporting -- never the basis itself.
        honest_chain_norms = _basis_chain_norms(pk, sk, target_kw, i, mu, params, pyrng)

        if h1_variant == "low_norm":
            R = H1(pk, i + 1, params)
            R_inv = np.array([[int(x) for x in row] for row in (H1_inverse(R) % q)], dtype=np.int64)
        else:
            raise ValueError("end-to-end attack is only meaningful for low_norm H1 (correctness must hold)")

        history.append(PeriodDB(
            period=i, pk_ri=pk, records=records, CT=CT, CM=CM,
            legit_trap_demo={"keyword": target_kw, "N0": N0_legit, **honest_chain_norms},
            R_into_next=R, ct_hash=_hash_ct(CT), cm_hash=_hash_cm(CM),
        ))

        pk_new = (pk @ R_inv) % q
        sk_new = new_basis_del(pk, R, sk, params.sigma, q, pyrng, R_inv=R_inv)
        if strengthen_legit:
            sk_new, _method = strong_reduce(sk_new)
        pk, sk = pk_new, sk_new

    stolen_pk, stolen_sk = pk, sk  # period J's key — never appears in `history`
    return history, stolen_pk, stolen_sk, mu, u_pke


def _recover_period_candidate(
    history: list[PeriodDB], i: int, J: int, stolen_sk_J: np.ndarray, params: Params, reducer=None,
) -> tuple[np.ndarray, bool, float, float, str]:
    """The actual R^-1-transform recovery (PATCH 01-04's machinery): the
    ONLY inputs are the stolen sk_J, and every public pk_r|k / R (read from
    `history`, all public fields — see test_attacker_never_reads_honest_sk).
    Returns (sk_star, membership_ok, trivial_norm, reduced_norm, method).
    """
    q, m = params.q, params.m
    # R_prod^-1 = R_{i+1}^-1 . R_{i+2}^-1 ... R_J^-1 (mod q) — all public.
    P_inv = np.eye(m, dtype=np.int64)
    for k in range(J - 1, i - 1, -1):
        R_inv_k = np.array([[int(x) for x in row] for row in (H1_inverse(history[k].R_into_next) % q)], dtype=np.int64)
        P_inv = (R_inv_k @ P_inv) % q
    P_inv_centered = centered_mod_q(P_inv, q)

    _cand_trivial, cand_reduced, reduced_ok, trivial_norm, reduced_norm, method = _recover_candidate(
        P_inv_centered, stolen_sk_J, history[i].pk_ri, q, reducer=reducer,
    )
    return cand_reduced, reduced_ok, trivial_norm, reduced_norm, method


def _test_candidate(
    history: list[PeriodDB], i: int, sk_star: np.ndarray, params: Params,
    mu: np.ndarray, u_pke: np.ndarray, source_label: str,
    membership_ok: bool = True, trivial_norm: float | None = None,
    reduced_norm: float | None = None, reducer_method: str | None = None,
    rng_tag: str = "attack", trace: Trace | None = None,
) -> dict:
    """Runs Level 1/2/3 for a GIVEN candidate basis `sk_star` against period
    i's FROZEN database — the shared testing logic used both by the real
    attack (attack_period) and by the negative controls
    (attack_period_negative_control), so both go through IDENTICALLY the
    same L2/L3 machinery. `source_label` records which one this was
    ("recovered", "garbage", "wrong_period") for reporting.
    """
    threshold = usability_threshold(params)["threshold"]
    if reduced_norm is None:
        reduced_norm = gram_schmidt_norm(sk_star)

    result = {
        "period": i,
        "source": source_label,
        "gs_norm": reduced_norm,
        "trivial_gs_norm": trivial_norm,
        "threshold": threshold,
        "reducer_method": reducer_method,
        "membership_ok": membership_ok,
        "level1_norm_ok": bool(reduced_norm <= threshold),
    }

    kw = history[i].legit_trap_demo["keyword"]
    N0_legit = history[i].legit_trap_demo["N0"]
    pyrng_local = random.Random(hash((i, source_label, rng_tag)) & 0xFFFFFFFF)

    # GATE (audit-caught, see module docstring): NewBasisDel's own Klein-
    # resampling step in this codebase does NOT enforce its correctness
    # precondition (sigma >= gs_norm(T_A) * omega(sqrt(log m)), i.e.
    # exactly Level 1's `threshold`) -- feed it an oversized or off-lattice
    # basis and it still returns SOMETHING, because its re-randomization
    # pool is dominated by fresh sigma-width Gaussian samples regardless of
    # input quality. Verified directly: a totally public, unreduced kernel
    # basis of pk_i (needing no secret, no theft) survives Trapdoor+Verify
    # about as often as the real key, even at default params with no
    # forward-security chain involved. Level 1 (norm) and lattice
    # membership are NECESSARY conditions the algorithm's own math
    # requires; a candidate that fails either is not a genuine trapdoor
    # input, so Level 2 must not even be attempted for it -- attempting it
    # anyway is exactly how the vacuous "any public garbage passes"
    # criterion happened. This is the stricter match definition the audit
    # asked for: passing Level 2 now requires ALSO clearing Level 1.
    N0_star = None
    if not (result["level1_norm_ok"] and membership_ok):
        result["level2_skipped_reason"] = (
            "candidate fails Level 1 (norm) and/or lattice membership -- "
            "NewBasisDel's own delegation precondition would be violated, "
            "so a trapdoor built from it would not reflect genuine "
            "delegation; not attempted."
        )
    else:
        try:
            trap_star = trapdoor(history[i].pk_ri, sk_star, kw, i, mu, params, pyrng_local, trace)
            N0_star = verify_search(history[i].CT, trap_star, params, trace)
        except Exception as e:  # noqa: BLE001 -- a recovered basis may simply be too degenerate to sample from
            result["level2_error"] = str(e)
    result["N0_legit"] = N0_legit
    result["N0_star"] = N0_star
    result["level2_search_break"] = bool(N0_star is not None and N0_star == N0_legit)

    # PATCH 06 §6.5 -- independent word-basis cross-check. SamplePre does
    # NOT consume the period basis (gs_norm above); it consumes a WORD
    # basis one MORE NewBasisDel delegation downstream, which GROWS the
    # norm. This is a SEPARATE prediction of Level 2 success, computed
    # from fresh Gaussian draws (not the same call used for N0_star above)
    # -- when it agrees with the measured level2_search_break, the result
    # is corroborated by two independent signals; when it disagrees, that
    # is flagged rather than silently trusted.
    honest = history[i].legit_trap_demo
    result["honest_period_gs"] = honest["period_gs"]
    result["honest_word_gs"] = honest["word_gs"]
    result["honest_trap_norm"] = honest["trap_norm"]
    result["honest_beta_norm"] = honest["beta_norm"]
    try:
        chain = _basis_chain_norms(history[i].pk_ri, sk_star, kw, i, mu, params, pyrng_local)
        result["word_gs"] = chain["word_gs"]
        result["trap_norm_predicted"] = chain["trap_norm"]
        result["beta_norm"] = chain["beta_norm"]
        result["word_pred_usable"] = bool(chain["word_gs"] <= threshold)
        result["l2_matches_wordpred"] = (result["word_pred_usable"] == result["level2_search_break"])
    except Exception as e:  # noqa: BLE001 -- off-lattice candidates have no well-defined word basis
        result["word_gs"] = None
        result["word_pred_usable"] = None
        result["l2_matches_wordpred"] = None
        result["word_gs_error"] = str(e)

    if LEVEL3_REACHABLE and result["level2_search_break"]:
        cm_entry = next(ct for (n_id, ct) in history[i].CM if n_id == N0_legit)
        M_true = next(M for (n_id, _kw, M) in history[i].records if n_id == N0_legit)
        try:
            M_star = decrypt_record(history[i].pk_ri, sk_star, cm_entry, u_pke, params, pyrng_local, trace)
            result["level3_plaintext_break"] = bool(M_star == M_true)
        except Exception as e:  # noqa: BLE001
            result["level3_plaintext_break"] = False
            result["level3_error"] = str(e)
    else:
        result["level3_plaintext_break"] = False
        result["level3_reachable"] = LEVEL3_REACHABLE

    # CRITICAL: prove the frozen DB was never touched by this attack.
    assert history[i].ct_hash == _hash_ct(history[i].CT), "frozen CT_i was mutated — invalid attack!"
    assert history[i].cm_hash == _hash_cm(history[i].CM), "frozen CM_i was mutated — invalid attack!"

    if result["level2_search_break"]:
        verdict = "L2 BROKEN (search recovered)"
        if result["level3_plaintext_break"]:
            verdict += " + L3 BROKEN (plaintext recovered)"
    elif not result["level1_norm_ok"]:
        verdict = "survives (norm exceeds threshold)"
    else:
        verdict = "survives (short enough, but search still failed)"
    result["verdict"] = verdict
    return result


def attack_period(
    history: list[PeriodDB], i: int, J: int, stolen_sk_J: np.ndarray, params: Params,
    mu: np.ndarray, u_pke: np.ndarray, reducer=None, trace: Trace | None = None,
) -> dict:
    """The backward attack against ONE frozen period. Attacker holds only:
    `stolen_sk_J`, every public pk_r|k / R (both in `history`), and the
    frozen `history[i]` ciphertexts — never the honest sk_r|i. See
    test_attacker_never_reads_honest_sk for the structural proof of this.
    """
    sk_star, membership_ok, trivial_norm, reduced_norm, method = _recover_period_candidate(
        history, i, J, stolen_sk_J, params, reducer=reducer,
    )
    result = _test_candidate(
        history, i, sk_star, params, mu, u_pke, source_label="recovered",
        membership_ok=membership_ok, trivial_norm=trivial_norm, reduced_norm=reduced_norm,
        reducer_method=method, rng_tag=str(J), trace=trace,
    )
    result["periods_back"] = J - i
    return result


def attack_period_negative_control(
    history: list[PeriodDB], i: int, params: Params, mu: np.ndarray, u_pke: np.ndarray,
    kind: str, wrong_period_sk: np.ndarray | None = None, trace: Trace | None = None,
) -> dict:
    """A NEGATIVE CONTROL: feeds a candidate that has NO legitimate
    relationship to period i's real key through the EXACT SAME L2/L3
    testing path (`_test_candidate`) as the real attack. If either of these
    "succeeds" at the same rate as a genuine recovery, the success
    criterion is vacuous and must be fixed BEFORE trusting any Level 2/3
    result (see the module docstring's audit note).

    - kind="garbage": the raw, unreduced kernel basis of pk_r|i itself —
      computable by ANYONE from the PUBLIC key alone, no theft needed.
    - kind="wrong_period": a genuine (well-formed, well-reduced) secret
      basis, but for the WRONG period — proves the attack isn't secretly
      succeeding just because "some valid-looking basis" was supplied.
    """
    if kind == "garbage":
        sk_candidate = kernel_basis_mod_q(history[i].pk_ri, params.q)
        # A kernel basis of pk_r|i IS (by construction) a genuine, if huge,
        # basis of L_perp_q(pk_r|i) -- honestly membership_ok=True; it's
        # Level 1 (norm) that must reject it, not membership.
        membership_ok = True
    elif kind == "wrong_period":
        if wrong_period_sk is None:
            raise ValueError("wrong_period_sk is required for kind='wrong_period'")
        sk_candidate = wrong_period_sk
        # wrong_period_sk is a real basis for a DIFFERENT period's lattice
        # -- report membership against THIS period's pk_r|i honestly,
        # rather than defaulting to True as if it were untested.
        membership_ok = bool(np.all(mat_mod_mixed(history[i].pk_ri, sk_candidate, params.q) == 0))
    else:
        raise ValueError("kind must be 'garbage' or 'wrong_period'")

    return _test_candidate(
        history, i, sk_candidate, params, mu, u_pke, source_label=kind,
        membership_ok=membership_ok, rng_tag="negctrl", trace=trace,
    )


def end_to_end_experiment(
    J: int, base_params: Params, n: int | None = None, seed: int = 0,
    h1_variant: str = "low_norm", reducer_name: str = "bkz",
) -> dict:
    """Runs the full forward pass (frozen history) then the backward attack
    against every period 0..J-1, at a given n (defaults to base_params.n).
    `reducer_name` is "bkz" (linalg.strong_reduce, fair PATCH-04 tooling) or
    "lll" (plain LLL, the weaker/original attacker).
    """
    if reducer_name not in ("bkz", "lll"):
        raise ValueError("reducer_name must be 'bkz' or 'lll'")
    n = n if n is not None else base_params.n
    p = Params(n=n, q=base_params.q, sigma=base_params.sigma, l=base_params.l,
               usability_C=base_params.usability_C, m=0)

    trace = Trace()
    trace.note(
        "Paper's Encrypt/Decrypt secret-material audit (blocking sub-task)",
        detail=LEVEL3_NOTE,
        data={"level3_reachable_in_principle": LEVEL3_REACHABLE},
        algo="EndToEnd",
        highlight=True,
    )

    history, stolen_pk, stolen_sk, mu, u_pke = build_frozen_history(
        J, p, seed=seed, h1_variant=h1_variant, strengthen_legit=True, trace=trace,
    )
    trace.threat_model(
        f"Attacker steals SK_r|{J} and holds every public pk_r|i, R_i, and the frozen databases",
        detail="Never the honest sk_r|i for i < J. The frozen CT_i/CM_i are the SAME "
               "ciphertexts the real doctor created and searched — never regenerated.",
        algo="EndToEnd",
        highlight=True,
    )

    reducer = strong_reduce if reducer_name == "bkz" else _lll_reducer
    rows = []
    for i in range(J):
        row = attack_period(history, i, J, stolen_sk, p, mu, u_pke, reducer=reducer, trace=trace)

        # Per-period negative controls (not just an aggregate line): run
        # BOTH kinds at THIS exact period, using the SAME frozen CT_i the
        # real attack just used, so a viewer inspecting one period's break
        # doesn't have to trust an aggregate summary computed elsewhere.
        g_ctrl = attack_period_negative_control(history, i, p, mu, u_pke, kind="garbage", trace=None)
        w_ctrl = attack_period_negative_control(
            history, i, p, mu, u_pke, kind="wrong_period", wrong_period_sk=stolen_sk, trace=None,
        )
        row["control_garbage_passed"] = g_ctrl["level2_search_break"]
        row["control_wrong_period_passed"] = w_ctrl["level2_search_break"]
        row["control_ok_this_period"] = not (row["control_garbage_passed"] or row["control_wrong_period_passed"])

        rows.append(row)
        trace.decision(
            f"Period {i} ({J - i} period(s) back): attacker's reconstructed SK*_r|{i}",
            verdict=row["verdict"],
            evidence={
                "gs_norm": row["gs_norm"], "threshold": row["threshold"],
                "N0_legit": row["N0_legit"], "N0_star": row["N0_star"],
                "level2_search_break": row["level2_search_break"],
                "level3_plaintext_break": row["level3_plaintext_break"],
                "control_garbage_passed": row["control_garbage_passed"],
                "control_wrong_period_passed": row["control_wrong_period_passed"],
            },
            algo="EndToEnd",
        )

    # Aggregate negative-control status across all periods, from the SAME
    # per-period controls just computed above (not a second, separate run)
    # so a viewer never has to trust a Level 2/3 verdict on faith: if
    # garbage or a wrong-period key ever passes, the run is untrustworthy.
    control_passed = [r["period"] for r in rows if r["control_garbage_passed"]]
    wrong_period_passed = [r["period"] for r in rows if r["control_wrong_period_passed"]]
    control_ok = not control_passed and not wrong_period_passed
    trace.decision(
        "Negative controls (garbage + wrong-period key) vs Level 2, per period",
        verdict="controls held everywhere (as required)" if control_ok
                else f"CONTROL FAILED -- garbage passed at {control_passed}, wrong-period passed at "
                     f"{wrong_period_passed} -- verdict below is UNTRUSTWORTHY",
        evidence={"garbage_passed_periods": control_passed, "wrong_period_passed_periods": wrong_period_passed},
        algo="EndToEnd",
        highlight=not control_ok,
    )

    broken_l2 = [r["period"] for r in rows if r["level2_search_break"]]
    broken_l3 = [r["period"] for r in rows if r["level3_plaintext_break"]]
    any_l2, any_l3 = bool(broken_l2), bool(broken_l3)
    wordpred_disagreements = [r["period"] for r in rows if r.get("l2_matches_wordpred") is False]

    if any_l2:
        headline = f"End-to-end forward-security break at n={n}, J={J}"
        conclusion = (
            f"A single stolen SK_r|{J} lets the attacker reconstruct SK*_r|i for earlier "
            f"periods. At n={n}, this recovers the OLD SEARCH capability for period(s) "
            f"{broken_l2} — the attacker's trapdoor returns the SAME sequence number N0 "
            f"the legitimate doctor obtained, on the untouched frozen ciphertext database "
            f"(Level 2 break). " + (
                f"Plaintext recovery (Level 3) also succeeds for period(s) {broken_l3}."
                if any_l3 else
                "Plaintext recovery (Level 3) did not succeed for any broken period — the "
                "recovered basis clears the search decode bound but not the (stricter) "
                "record decode bound."
            ) + " This is a functionality-level forward-security break at demonstration "
                "parameters, confined to periods near the compromise; whether it reaches "
                "cryptographic parameters is open (needs large-n BKZ estimates)."
        )
    else:
        headline = f"Resists this end-to-end attack at n={n}, J={J}"
        conclusion = (
            "The recovered basis never yields a working old trapdoor at this n — the norm "
            "proxy overstated the threat; forward-security functionality resists this "
            "specific attack here."
        )

    if not control_ok:
        headline = f"UNTRUSTWORTHY RUN at n={n}, J={J} -- negative control failed"
        conclusion = (
            f"A negative control passed Level 2 in THIS run -- garbage (public, secret-free "
            f"kernel basis) at period(s) {control_passed}, a wrong-period key at period(s) "
            f"{wrong_period_passed} -- so the Level 2 test is not discriminating a genuine "
            f"recovered key from an input with no legitimate relationship to that period here, "
            f"and the measured verdict above cannot be trusted. Do not report a break or a "
            f"resist from this run; investigate the calibration (see the module docstring) "
            f"before trusting any result at these parameters."
        )

    caveats = [
        f"Demonstration parameters (n={n}). Even a search/decrypt-level break here does "
        f"not establish a break at secure parameters — that needs a proof or a large-n "
        f"BKZ cost estimate, neither of which this lab performs.",
        "This tests ONE attack family (public R^-1 transform + lattice reduction). "
        "'Resists this attack' is not the same claim as 'provably forward-secure'.",
        "Level 2 (search) and Level 3 (decrypt) are different claims — a period can "
        "break L2 (recover the old search capability) without breaking L3 (recover the "
        "old plaintext), since Level 3 needs a stricter decode margin.",
    ]
    if wordpred_disagreements:
        caveats.append(
            f"The independent word-basis norm prediction (PATCH 06 §6.5) DISAGREED with the "
            f"measured Level 2 outcome at period(s) {wordpred_disagreements} — inspect those "
            f"rows' word_gs/threshold and word_gs_error before trusting them."
        )

    trace.result(headline, detail=conclusion, data={"broken_periods_l2": broken_l2, "broken_periods_l3": broken_l3},
                 algo="EndToEnd", highlight=True)

    return {
        "J": J, "n": n, "m": p.m, "reducer_name": reducer_name, "reducer_method": rows[0]["reducer_method"] if rows else None,
        "rows": rows,
        "any_l2_break": any_l2, "any_l3_break": any_l3,
        "broken_periods_l2": broken_l2, "broken_periods_l3": broken_l3,
        "headline": headline, "conclusion": conclusion,
        "level3_reachable_in_principle": LEVEL3_REACHABLE,
        "control_ok": control_ok, "control_passed_periods": control_passed,
        "wrong_period_control_passed_periods": wrong_period_passed,
        "wordpred_disagreements": wordpred_disagreements,
        "trustworthy": control_ok,
        "caveats": caveats,
        "trace": trace.to_list(),
    }


def end_to_end_multi_n(
    J: int, base_params: Params, n_values: tuple[int, ...] = DEFAULT_END_TO_END_N_VALUES,
    seed: int = 0, reducer_name: str = "bkz",
) -> dict:
    """Runs end_to_end_experiment at each n in `n_values` (PATCH 05 §3: "run
    at n=4 and n=6" — here n=4 and n=8, since n=6 has no valid H2 for
    q=257) and reports the honest headline across dimensions. Each n's own
    trace is kept in its row; the combined trace returned here is just the
    note/result-level summary events, to keep the payload manageable.
    """
    per_n = []
    for n in n_values:
        try:
            per_n.append(end_to_end_experiment(J, base_params, n=n, seed=seed, reducer_name=reducer_name))
        except Exception as e:  # noqa: BLE001 -- e.g. an n incompatible with H2 for this q
            per_n.append({"n": n, "error": str(e)})

    ok = [r for r in per_n if "error" not in r]
    untrustworthy_ns = sorted({r["n"] for r in ok if not r.get("control_ok", True)})
    trustworthy_ok = [r for r in ok if r.get("control_ok", True)]
    any_l2 = any(r["any_l2_break"] for r in trustworthy_ok)
    broken_ns = sorted({r["n"] for r in trustworthy_ok if r["any_l2_break"]})
    clean_ns = sorted({r["n"] for r in trustworthy_ok if not r["any_l2_break"]})

    if untrustworthy_ns:
        summary = (
            f"UNTRUSTWORTHY at n={untrustworthy_ns}, J={J}: the negative control failed there "
            f"(garbage passed Level 2), so those rows' verdicts cannot be trusted — see each "
            f"row's own conclusion. " + (
                f"Remaining trustworthy dimensions: broken at n={broken_ns}, resists at "
                f"n={clean_ns}." if trustworthy_ok else "No trustworthy dimension in this run."
            )
        )
    elif any_l2 and clean_ns:
        summary = (
            f"Finding 2 — end-to-end forward-security demonstration at J={J} (low-norm H1, "
            f"fair BKZ tooling, negative control held at every tested n): the old search "
            f"capability (Level 2) is recovered at n={broken_ns} but not at n={clean_ns}. This "
            f"is a functionality-level forward-security break at demonstration parameters, "
            f"confined to the smaller dimension(s) tested; whether it reaches cryptographic "
            f"parameters is open (needs large-n BKZ estimates)."
        )
    elif any_l2:
        summary = (
            f"Finding 2 — end-to-end forward-security break confirmed at every tested "
            f"dimension (n={broken_ns}, J={J}), negative control held throughout. The "
            f"recovered basis yields a working old trapdoor even under fair (BKZ vs BKZ) "
            f"tooling."
        )
    else:
        summary = (
            f"At J={J}, the recovered basis never yields a working old trapdoor at any tested "
            f"n (negative control held throughout) — the norm proxy overstated the threat; "
            f"forward-security functionality resists this attack at the dimensions tested here."
        )

    return {
        "J": J,
        "n_values": list(n_values),
        "per_n": per_n,
        "any_l2_break": any_l2,
        "broken_ns": broken_ns,
        "clean_ns": clean_ns,
        "untrustworthy_ns": untrustworthy_ns,
        "summary": summary,
    }
