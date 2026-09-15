"""The seven PPSEB algorithms — Initialization, KeyExt, PEKS.Encrypt,
Trapdoor, Verify, Encrypt, Decrypt — faithful to Xu et al. 2022 except where
the paper is unspecified or broken, in which case we implement the CORRECTED
version and mark the deviation with a `correction` trace event (CLAUDE.md §3).
"""

from __future__ import annotations

import random

import numpy as np

from .hashes import H1, H1_inverse, H2, H2_inverse
from .linalg import mat_inv_mod, mat_mod_mixed, safe_matmul
from .params import Params
from .samplers import new_basis_del, sample_pre
from .trace import Trace
from .trapgen import trapgen

# Ciphertext/encryption noise (PEKS CT1/CT2 and the record PKE) is *much*
# smaller than the lattice-sampling width `params.sigma`: it just needs to
# stay well under the q/4 decode threshold once combined with a short
# trapdoor vector, whereas `sigma` sets the width of the discrete-Gaussian
# lattice sampler (SamplePre / NewBasisDel). The paper does not specify a
# concrete noise width for either; this is a reasonable, documented choice.
# Exposed as `params.ciphertext_noise_sigma` (see Params' own docstring for
# why this needs to be a per-run value, not a fixed constant, once PATCH 05
# starts actually running Verify against a dimension-aware sigma). This
# module constant is now only the field's default.
CIPHERTEXT_NOISE_SIGMA = 0.4


def _small_noise(shape: tuple[int, ...], sigma: float, rng: random.Random) -> np.ndarray:
    from .linalg import discrete_gaussian_1d
    flat = [discrete_gaussian_1d(0.0, sigma, rng) for _ in range(int(np.prod(shape)))]
    return np.array(flat, dtype=np.int64).reshape(shape)


# --------------------------------------------------------------------------
# Initialization
# --------------------------------------------------------------------------

def initialization(params: Params, rng: np.random.Generator, trace: Trace | None = None) -> dict:
    """Generates the root (period-0) keypair, the LWE-secret-like `mu`, and a
    fixed public anchor vector `u_pke` used by the record Encrypt/Decrypt
    track. Returns a dict; the API layer holds this as session state.
    """
    if trace is not None:
        trace.note(
            "Type discipline (CLAUDE.md §3.1)",
            detail="The paper never states these shapes; we fix them once here so every later step is checkable.",
            data=params.shape_table(),
            algo="Initialization",
        )

    A0, T0 = trapgen(params, rng, trace)
    mu = rng.integers(0, params.q, size=params.n).astype(np.int64)
    u_pke = rng.integers(0, params.q, size=params.n).astype(np.int64)

    if trace is not None:
        trace.result(
            "Initialization complete",
            detail="Root public key pk_r0, root trapdoor sk_r0, shared secret mu, and record-PKE anchor u_pke are established.",
            data={"mu_preview": mu[:12].tolist(), "u_pke_preview": u_pke[:12].tolist()},
            algo="Initialization",
        )

    return {"pk_r0": A0, "sk_r0": T0, "mu": mu, "u_pke": u_pke}


# --------------------------------------------------------------------------
# KeyExt — corrected, single-step, non-circular (CLAUDE.md §3.8)
# --------------------------------------------------------------------------

def keyext(
    j: int, pk_prev: np.ndarray, sk_prev: np.ndarray, params: Params,
    rng: random.Random, trace: Trace | None = None,
) -> tuple[np.ndarray, np.ndarray]:
    """pk_j, sk_j = KeyExt(j, pk_{j-1}, sk_{j-1}). The paper's Algorithm 2
    prints two circular dependencies (see attacks/spec_defect.py for the
    airtight demonstration); this is the corrected single-step version.
    """
    if trace is not None:
        trace.correction(
            "KeyExt Correction A: NewBasisDel must take the SOURCE basis",
            paper_says="Algorithm 2 line 7 calls NewBasisDel with sk_rj — the "
                       "basis being produced by this very call — as an input.",
            we_do="NewBasisDel(pk_{j-1}, R, sk_{j-1}, sigma): the input basis "
                  "is the previous period's trapdoor sk_{j-1}, which already exists.",
            because="A function cannot take its own output as an input; "
                    "NewBasisDel's whole purpose (ABB basis delegation) is to "
                    "derive a new basis FROM an existing one.",
            algo="KeyExt",
        )
        trace.correction(
            "KeyExt Correction B: R must reference only period j-1",
            paper_says="Algorithm 2 line 6 computes R = H1(pk_rj, j) — using "
                       "pk_rj, the public key this very call is supposed to produce.",
            we_do="R = H1(pk_{j-1}, j): R is derived only from the previous "
                  "period's public key and the period index.",
            because="pk_rj does not exist yet when R is computed — using it "
                    "creates a forward reference / circular definition, "
                    "making the algorithm as printed non-executable.",
            algo="KeyExt",
        )

    R = H1(pk_prev, j, params, trace)
    R_inv_exact = H1_inverse(R)
    # Mod-reduce, then normalize dtype: R_inv_exact may still be `object`
    # dtype (H1_inverse's exact pre-reduction values can be large), but once
    # reduced mod q every entry is small, so it's safe (and needed, to avoid
    # a mixed int64/object matmul) to bring it back to int64 here.
    R_inv = np.array([[int(x) for x in row] for row in (R_inv_exact % params.q)], dtype=np.int64)
    pk_j = (pk_prev @ R_inv) % params.q
    sk_j = new_basis_del(pk_prev, R, sk_prev, params.sigma, params.q, rng, trace, R_inv=R_inv)

    ok = bool(np.all(mat_mod_mixed(pk_j, sk_j, params.q) == 0))
    if trace is not None:
        trace.decision(
            f"KeyExt period {j}: verified pk_{j} . sk_{j} = 0 (mod q)",
            verdict="valid key pair" if ok else "INVALID",
            evidence={"all_columns_zero_mod_q": ok},
            algo="KeyExt",
        )
    if not ok:
        raise RuntimeError(f"KeyExt: pk_{j}.sk_{j} != 0 (mod q); this should never happen")
    return pk_j, sk_j


# --------------------------------------------------------------------------
# PEKS.Encrypt — the B_j-sharing fix (CLAUDE.md §3.5)
# --------------------------------------------------------------------------

def peks_encrypt(
    pk_rj: np.ndarray, w: str, j: int, mu: np.ndarray, params: Params,
    rng: np.random.Generator, py_rng: random.Random, trace: Trace | None = None,
) -> dict:
    n, m, l, q = params.n, params.m, params.l, params.q
    beta = H2(w, j, params, trace)
    beta_inv = H2_inverse(beta, q)

    B = rng.integers(0, q, size=(n, l)).astype(np.int64)
    noise1 = _small_noise((l,), params.ciphertext_noise_sigma, py_rng)
    noise2 = _small_noise((m, l), params.ciphertext_noise_sigma, py_rng)
    half_q = q // 2
    y_ones = np.ones(l, dtype=np.int64)

    CT1 = (mu @ B + noise1 + y_ones * half_q) % q
    CT2 = (((pk_rj @ beta_inv) % q).T @ B + noise2) % q

    if trace is not None:
        trace.correction(
            "PEKS.Encrypt: B_j must be SHARED between CT1 and CT2",
            paper_says="The paper is ambiguous about whether the random "
                       "matrix B_j used to build CT1 is the same B_j used for CT2.",
            we_do="Sample one B (n x l) and use it for both CT1 = mu^T B + ... "
                  "and CT2 = (pk_rj.beta^-1)^T B + ....",
            because="Verify's cancellation, Trap^T CT2 = mu^T B + (small noise), "
                    "only works if CT1 and CT2 were built against the SAME B — "
                    "with independent B's the B-dependent terms never cancel and "
                    "Verify always rejects, even for a matching keyword. This "
                    "unstated shared-B assumption is load-bearing and undocumented.",
            data={"B_shape": [n, l]},
            algo="PEKS",
        )
        trace.matrix("Shared matrix B", B, name="B", algo="PEKS")
        trace.result(
            f"PEKS.Encrypt(w={w!r}, j={j}) complete",
            data={"CT1_preview": CT1[:12].tolist(), "CT2_shape": list(CT2.shape)},
            algo="PEKS",
        )

    return {"B": B, "CT1": CT1, "CT2": CT2}


# --------------------------------------------------------------------------
# Trapdoor
# --------------------------------------------------------------------------

def trapdoor(
    pk_rj: np.ndarray, sk_rj: np.ndarray, w_query: str, j: int, mu: np.ndarray,
    params: Params, rng: random.Random, trace: Trace | None = None,
) -> np.ndarray:
    beta = H2(w_query, j, params, trace)
    beta_inv = H2_inverse(beta, params.q)

    if trace is not None:
        trace.compute(
            "Trapdoor: delegating a keyword-specific basis",
            detail="sk_w = NewBasisDel(pk_rj, beta, sk_rj, sigma) — beta plays the role of the low-norm invertible transform (as R did in KeyExt).",
            algo="Trapdoor",
        )
    sk_w = new_basis_del(pk_rj, beta, sk_rj, params.sigma, params.q, rng, trace, R_inv=beta_inv)

    A_w = (pk_rj @ beta_inv) % params.q
    Trap = sample_pre(A_w, sk_w, mu, params.sigma, params.q, rng, trace)

    if trace is not None:
        trace.result(
            f"Trapdoor(w={w_query!r}, j={j}) complete",
            detail="Trap is a short vector with (pk_rj . beta^-1) . Trap = mu (mod q).",
            data={"Trap_preview": Trap[:12].tolist(), "Trap_norm": float(np.linalg.norm(Trap.astype(float)))},
            algo="Trapdoor",
        )
    return Trap


# --------------------------------------------------------------------------
# Verify
# --------------------------------------------------------------------------

def verify(CT1: np.ndarray, CT2: np.ndarray, Trap: np.ndarray, params: Params, trace: Trace | None = None) -> tuple[bool, np.ndarray]:
    q = params.q
    y = (CT1 - safe_matmul(Trap, CT2)) % q
    half_q = q // 2
    centered_dist = np.minimum(np.abs(y - half_q), q - np.abs(y - half_q))
    threshold = q // 4
    match = bool(np.all(centered_dist < threshold))

    if trace is not None:
        trace.note(
            "Verify's decode threshold: q/4 vs the paper's q/5",
            detail="The paper's correctness proof (§5.1) bounds the noise by q/5, "
                   "but the natural decision rule for 'close to floor(q/2)' uses "
                   "a q/4 half-width (the standard LWE rounding threshold). We "
                   "use q/4 and flag the mismatch rather than silently picking one.",
            data={"q": q, "q_over_4": threshold, "q_over_5": q // 5},
            algo="Verify",
        )
        trace.decision(
            "Verify result",
            verdict="MATCH" if match else "no match",
            evidence={
                "y_preview": y[:12].tolist(),
                "max_distance_from_q_over_2": int(np.max(centered_dist)),
                "threshold_q_over_4": threshold,
            },
            algo="Verify",
        )
    return match, y


# --------------------------------------------------------------------------
# Encrypt / Decrypt — minimal dual-Regev PKE for the medical record bytes
# --------------------------------------------------------------------------

def encrypt_record(
    pk_rj: np.ndarray, record: bytes, u_pke: np.ndarray, params: Params,
    rng: np.random.Generator, py_rng: random.Random, trace: Trace | None = None,
) -> dict:
    """Minimal dual-Regev bit-encryption of `record` under pk_rj. Not one of
    the three findings — kept small so the happy-path demo has something
    concrete to decrypt at the end (CLAUDE.md §3.10)."""
    n, m, q = params.n, params.m, params.q
    bits = np.unpackbits(np.frombuffer(record, dtype=np.uint8))
    half_q = q // 2

    C1 = np.zeros((len(bits), m), dtype=np.int64)
    C2 = np.zeros(len(bits), dtype=np.int64)
    for i, b in enumerate(bits):
        s = rng.integers(0, q, size=n).astype(np.int64)
        e = _small_noise((m,), params.ciphertext_noise_sigma, py_rng)
        e_prime = int(_small_noise((1,), params.ciphertext_noise_sigma, py_rng)[0])
        C1[i] = (pk_rj.T @ s + e) % q
        C2[i] = (int(u_pke @ s) + e_prime + int(b) * half_q) % q

    if trace is not None:
        trace.result(
            f"Encrypt: {len(record)} record bytes -> {len(bits)} dual-Regev bit-ciphertexts",
            data={"num_bits": int(len(bits))},
            algo="Encrypt",
        )
    return {"C1": C1, "C2": C2, "num_bytes": len(record)}


def decrypt_record(
    pk_rj: np.ndarray, sk_rj: np.ndarray, ciphertext: dict, u_pke: np.ndarray,
    params: Params, rng: random.Random, trace: Trace | None = None,
) -> bytes:
    q = params.q
    t0 = sample_pre(pk_rj, sk_rj, u_pke, params.sigma, q, rng, trace)
    C1, C2, num_bytes = ciphertext["C1"], ciphertext["C2"], ciphertext["num_bytes"]
    half_q = q // 2

    vals = (C2 - safe_matmul(C1, t0)) % q
    vals = vals.astype(np.int64)
    dist_to_0 = np.minimum(vals, q - vals)
    dist_to_half = np.abs(vals - half_q)
    bits = (dist_to_half < dist_to_0).astype(np.uint8)
    record = np.packbits(bits)[:num_bytes].tobytes()

    if trace is not None:
        trace.result(
            "Decrypt: record recovered",
            detail="t0 = SamplePre(pk_rj, sk_rj, u_pke, sigma) is the dual-Regev decryption key; each bit decoded by nearest-of-{0, q/2}.",
            data={"num_bytes": num_bytes},
            algo="Decrypt",
        )
    return record
