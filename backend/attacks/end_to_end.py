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

**A second interaction discovered the same way:** PATCH 03's dimension-aware
sigma (needed for NewBasisDel's own correctness) makes Trap's own norm grow,
which — at the ORIGINAL fixed ciphertext-noise width — can blow Verify's
decode margin and break even the LEGITIMATE doctor's own search (never
visible before PATCH 05, which is the first patch to actually run PEKS/
Trapdoor/Verify rather than just measure norms). Fixed by exposing the
ciphertext noise width as `Params.ciphertext_noise_sigma` and scaling it down
in proportion to how far sigma was scaled up (`build_frozen_history`),
preserving the original, already-tuned sigma*noise product.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

import numpy as np

from ppseb.hashes import H1, H1_inverse
from ppseb.linalg import centered_mod_q, gram_schmidt_norm, mat_mod_mixed
from ppseb.params import Params
from ppseb.samplers import new_basis_del
from ppseb.scheme import decrypt_record, encrypt_record, peks_encrypt, trapdoor, verify
from ppseb.trace import Trace
from ppseb.trapgen import trapgen

from .forward_sec import _lll_reducer, _recover_candidate, sigma_for_params, usability_threshold
from ppseb.linalg import strong_reduce

DICTIONARY = (
    "flu", "asthma", "diabetes", "hypertension", "migraine", "eczema",
    "bronchitis", "arthritis",
)
RECORDS_PER_PERIOD = 4
GROUND_TRUTH_IDX = 0

# n=6 (PATCH 04's own choice) has no valid H2 twist for q=257 — see the
# module docstring's dimension-constraint note. n=4 and n=8 are both powers
# of 2 (compatible with q-1=256) and span the same "does it survive a
# larger dimension" question PATCH 04's fairness sweep asked.
DEFAULT_END_TO_END_N_VALUES = (4, 8)

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
    base_sigma, base_noise = params.sigma, params.ciphertext_noise_sigma
    params.sigma = sigma_for_params(sk0, params)
    # PATCH 05 discovery: PATCH 03's dimension-aware sigma fixes NewBasisDel's
    # OWN correctness, but Trap's norm scales with sigma too — at a FIXED
    # ciphertext noise width, a larger sigma can blow Verify's decode margin
    # and break even the LEGITIMATE doctor's own search (never an issue in
    # PATCH 01-04, which only ever measured norms and never actually ran
    # PEKS/Trapdoor/Verify). Rescale the noise width in proportion to how
    # far sigma was scaled up, preserving the ORIGINAL (already-tuned)
    # sigma*noise product rather than fixing one correctness bound by
    # breaking another.
    params.ciphertext_noise_sigma = base_noise * (base_sigma / params.sigma)
    if strengthen_legit:
        sk0, _method = strong_reduce(sk0)
        assert bool(np.all(mat_mod_mixed(pk0, sk0, q) == 0)), "strong_reduce left L_perp_q(pk0)"

    mu = rng.integers(0, q, size=params.n).astype(np.int64)
    u_pke = rng.integers(0, q, size=params.n).astype(np.int64)

    history: list[PeriodDB] = []
    pk, sk = pk0, sk0
    for i in range(J):
        kws = pyrng.sample(list(dictionary), min(RECORDS_PER_PERIOD, len(dictionary)))
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

        if h1_variant == "low_norm":
            R = H1(pk, i + 1, params)
            R_inv = np.array([[int(x) for x in row] for row in (H1_inverse(R) % q)], dtype=np.int64)
        else:
            raise ValueError("end-to-end attack is only meaningful for low_norm H1 (correctness must hold)")

        history.append(PeriodDB(
            period=i, pk_ri=pk, records=records, CT=CT, CM=CM,
            legit_trap_demo={"keyword": target_kw, "N0": N0_legit},
            R_into_next=R, ct_hash=_hash_ct(CT), cm_hash=_hash_cm(CM),
        ))

        pk_new = (pk @ R_inv) % q
        sk_new = new_basis_del(pk, R, sk, params.sigma, q, pyrng, R_inv=R_inv)
        if strengthen_legit:
            sk_new, _method = strong_reduce(sk_new)
        pk, sk = pk_new, sk_new

    stolen_pk, stolen_sk = pk, sk  # period J's key — never appears in `history`
    return history, stolen_pk, stolen_sk, mu, u_pke


def attack_period(
    history: list[PeriodDB], i: int, J: int, stolen_sk_J: np.ndarray, params: Params,
    mu: np.ndarray, u_pke: np.ndarray, reducer=None, trace: Trace | None = None,
) -> dict:
    """The backward attack against ONE frozen period. Attacker holds only:
    `stolen_sk_J`, every public pk_r|k / R (both in `history`), and the
    frozen `history[i]` ciphertexts — never the honest sk_r|i.
    """
    q, m = params.q, params.m

    # R_prod^-1 = R_{i+1}^-1 . R_{i+2}^-1 ... R_J^-1 (mod q) — all public.
    P_inv = np.eye(m, dtype=np.int64)
    for k in range(J - 1, i - 1, -1):
        R_inv_k = np.array([[int(x) for x in row] for row in (H1_inverse(history[k].R_into_next) % q)], dtype=np.int64)
        P_inv = (R_inv_k @ P_inv) % q
    P_inv_centered = centered_mod_q(P_inv, q)

    cand_trivial, cand_reduced, reduced_ok, trivial_norm, reduced_norm, method = _recover_candidate(
        P_inv_centered, stolen_sk_J, history[i].pk_ri, q, reducer=reducer,
    )
    sk_star = cand_reduced
    threshold = usability_threshold(params)["threshold"]

    result = {
        "period": i,
        "periods_back": J - i,
        "gs_norm": reduced_norm,
        "trivial_gs_norm": trivial_norm,
        "threshold": threshold,
        "reducer_method": method,
        "membership_ok": reduced_ok,
        "level1_norm_ok": bool(reduced_norm <= threshold),
    }

    kw = history[i].legit_trap_demo["keyword"]
    N0_legit = history[i].legit_trap_demo["N0"]
    pyrng_local = random.Random(hash((i, J, "attack")) & 0xFFFFFFFF)

    N0_star = None
    try:
        trap_star = trapdoor(history[i].pk_ri, sk_star, kw, i, mu, params, pyrng_local, trace)
        N0_star = verify_search(history[i].CT, trap_star, params, trace)
    except Exception as e:  # noqa: BLE001 -- a recovered basis may simply be too degenerate to sample from
        result["level2_error"] = str(e)
    result["N0_legit"] = N0_legit
    result["N0_star"] = N0_star
    result["level2_search_break"] = bool(N0_star is not None and N0_star == N0_legit)

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
        rows.append(row)
        trace.decision(
            f"Period {i} ({J - i} period(s) back): attacker's reconstructed SK*_r|{i}",
            verdict=row["verdict"],
            evidence={
                "gs_norm": row["gs_norm"], "threshold": row["threshold"],
                "N0_legit": row["N0_legit"], "N0_star": row["N0_star"],
                "level2_search_break": row["level2_search_break"],
                "level3_plaintext_break": row["level3_plaintext_break"],
            },
            algo="EndToEnd",
        )

    broken_l2 = [r["period"] for r in rows if r["level2_search_break"]]
    broken_l3 = [r["period"] for r in rows if r["level3_plaintext_break"]]
    any_l2, any_l3 = bool(broken_l2), bool(broken_l3)

    if any_l2:
        headline = f"End-to-end forward-security break at n={n}"
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
        headline = f"Resists this end-to-end attack at n={n}"
        conclusion = (
            "The recovered basis never yields a working old trapdoor at this n — the norm "
            "proxy overstated the threat; forward-security functionality resists this "
            "specific attack here."
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
        "caveats": [
            f"Demonstration parameters (n={n}). Even a search/decrypt-level break here does "
            f"not establish a break at secure parameters — that needs a proof or a large-n "
            f"BKZ cost estimate, neither of which this lab performs.",
            "This tests ONE attack family (public R^-1 transform + lattice reduction). "
            "'Resists this attack' is not the same claim as 'provably forward-secure'.",
            "Level 2 (search) and Level 3 (decrypt) are different claims — a period can "
            "break L2 (recover the old search capability) without breaking L3 (recover the "
            "old plaintext), since Level 3 needs a stricter decode margin.",
        ],
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
    any_l2 = any(r["any_l2_break"] for r in ok)
    broken_ns = sorted({r["n"] for r in ok if r["any_l2_break"]})
    clean_ns = sorted({r["n"] for r in ok if not r["any_l2_break"]})

    if any_l2 and clean_ns:
        summary = (
            f"Finding 2 — end-to-end forward-security demonstration (low-norm H1, fair BKZ "
            f"tooling): the old search capability (Level 2) is recovered at n={broken_ns} but "
            f"not at n={clean_ns}. This is a functionality-level forward-security break at "
            f"demonstration parameters, confined to the smaller dimension(s) tested; whether "
            f"it reaches cryptographic parameters is open (needs large-n BKZ estimates)."
        )
    elif any_l2:
        summary = (
            f"Finding 2 — end-to-end forward-security break confirmed at every tested "
            f"dimension (n={broken_ns}). The recovered basis yields a working old trapdoor "
            f"even under fair (BKZ vs BKZ) tooling."
        )
    else:
        summary = (
            "The recovered basis never yields a working old trapdoor at any tested n — the "
            "norm proxy overstated the threat; forward-security functionality resists this "
            "attack at the dimensions tested here."
        )

    return {
        "J": J,
        "n_values": list(n_values),
        "per_n": per_n,
        "any_l2_break": any_l2,
        "broken_ns": broken_ns,
        "clean_ns": clean_ns,
        "summary": summary,
    }
