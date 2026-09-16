"""Micciancio-Peikert (MP12) gadget trapdoors.

"Trapdoors for Lattices: Simpler, Tighter, Faster, Smaller", EUROCRYPT 2012
(eprint 2011/501); G-sampling parameters after Genise-Micciancio (eprint
2017/308). Replaces the raw-kernel-basis + LLL TrapGen (PATCH 10).

Width convention. MP12 states Gaussian widths as the *Gaussian parameter* s,
density ~ exp(-pi x^2 / s^2). This codebase's samplers
(`linalg.discrete_gaussian_1d`, `klein_sample`) take a standard deviation.
They differ by sqrt(2*pi); `_std` does the conversion, and every value
reported by `mp12_parameters` is a Gaussian parameter.

Construction, with b = 2, k = ceil(log2 q), m = 2nk, m_bar = m - nk = nk:
- g = (1, 2, ..., 2^{k-1}); G = I_n (x) g^T in Z_q^{n x nk}.
- S_k: a basis of L_perp_q(g^T) with GS norm <= sqrt(5); S = I_n (x) S_k.
- TrapGen: A = [A_bar | G - A_bar R] with small R, so A [R; I] = G.
- The trapdoor R also yields an explicit short basis of L_perp_q(A)
  (MP12 Lemma 5.3): S_A = [[I + R W, R S], [W, S]] where G W = -A_bar.
- SamplePre: perturbation p with covariance s^2 I - alpha^2 [R;I][R;I]^T
  (Peikert's convolution, so the output does not reveal R), a gadget sample
  z with G z = u - A p, and x = p + [R; I] z.
"""

from __future__ import annotations

import math
import random

import numpy as np

from .linalg import discrete_gaussian_1d, gram_schmidt_norm, klein_sample
from .params import Params
from .trace import Trace

BASE = 2
EPSILON_LOG2 = -40  # epsilon = 2^-40 for every smoothing-parameter estimate
PERTURBATION_MARGIN = 1.1  # final width s is this factor above the minimum convolution needs


def _std(gaussian_parameter: float) -> float:
    return gaussian_parameter / math.sqrt(2 * math.pi)


def gadget_k(q: int) -> int:
    return math.ceil(math.log2(q))


def gadget_vector(q: int) -> np.ndarray:
    return np.array([BASE ** i for i in range(gadget_k(q))], dtype=np.int64)


def gadget_matrix(n: int, q: int) -> np.ndarray:
    """G = I_n (x) g^T, n x nk."""
    return np.kron(np.eye(n, dtype=np.int64), gadget_vector(q).reshape(1, -1))


def gadget_basis_k(q: int) -> np.ndarray:
    """S_k: basis of L_perp_q(g^T) for arbitrary q (MP12 §4.2).

    Column j < k-1 is 2 e_j - e_{j+1}; the last column is q's binary digits,
    so g^T S_k = 0 mod q and |det S_k| = q. Its Gram-Schmidt norm is at most
    sqrt(5).
    """
    k = gadget_k(q)
    S = np.zeros((k, k), dtype=np.int64)
    for j in range(k - 1):
        S[j, j] = BASE
        S[j + 1, j] = -1
    S[:, k - 1] = [(q >> i) & 1 for i in range(k)]
    return S


def smoothing_parameter_z(dim: int = 1) -> float:
    """eta_epsilon(Z^dim) ~ sqrt(ln(2 dim (1 + 1/eps)) / pi), as a Gaussian parameter."""
    inv_eps = 2.0 ** (-EPSILON_LOG2)
    return math.sqrt(math.log(2 * dim * (1 + inv_eps)) / math.pi)


def binary_decompose(v: np.ndarray, q: int) -> np.ndarray:
    """Base-2 digits (k per entry, least significant first) of v mod q, so G @ digits = v."""
    k = gadget_k(q)
    v = np.asarray(v, dtype=np.int64) % q
    out = np.zeros((v.shape[0] * k,) + v.shape[1:], dtype=np.int64)
    for i in range(k):
        out[i::k] = (v >> i) & 1
    return out


def mp12_parameters(params: Params, R: np.ndarray) -> dict:
    """Every width MP12 SamplePre uses, derived from params and this trapdoor."""
    q, m = params.q, params.m
    S_k = gadget_basis_k(q)
    gs_sk = gram_schmidt_norm(S_k.astype(float))
    eta_z = smoothing_parameter_z(1)
    alpha = (BASE + 1) * eta_z  # Genise-Micciancio: >= ||S_k~|| eta_eps(Z), since b+1 >= sqrt(5)
    r = smoothing_parameter_z(m)  # rounding width for the perturbation
    T = np.vstack([R, np.eye(R.shape[1], dtype=np.int64)])
    s1_T = float(np.linalg.norm(T.astype(float), 2))
    s_min = math.sqrt((alpha * s1_T) ** 2 + r ** 2)
    s = PERTURBATION_MARGIN * s_min
    return {
        "base": BASE, "k": gadget_k(q), "epsilon": f"2^{EPSILON_LOG2}",
        "gs_norm_S_k": gs_sk, "eta_epsilon_Z": eta_z,
        "alpha": alpha, "r": r, "s1_R": float(np.linalg.norm(R.astype(float), 2)), "s1_T": s1_T,
        "s_min": s_min, "s": s, "margin": PERTURBATION_MARGIN,
        "convention": "Gaussian parameter (std = s / sqrt(2 pi))",
        "preimage_norm_bound": s * math.sqrt(m),
    }


def mp12_trapgen(
    params: Params, rng: np.random.Generator, r_bound: int = 1, trace: Trace | None = None,
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Returns (A, R, S_A): public key A (n x m), gadget trapdoor R
    (m_bar x nk, entries uniform in [-r_bound, r_bound]), and the explicit
    short basis S_A of L_perp_q(A) derived from R (MP12 Lemma 5.3)."""
    n, q, m = params.n, params.q, params.m
    k = gadget_k(q)
    nk = n * k
    m_bar = m - nk
    if m_bar < 1:
        raise ValueError(f"MP12 needs m > nk; got m={m}, nk={nk}")

    G = gadget_matrix(n, q)
    A_bar = rng.integers(0, q, size=(n, m_bar)).astype(np.int64)
    R = rng.integers(-r_bound, r_bound + 1, size=(m_bar, nk)).astype(np.int64)
    A = np.hstack([A_bar, (G - A_bar @ R) % q]) % q

    S = np.kron(np.eye(n, dtype=np.int64), gadget_basis_k(q))
    W = binary_decompose((-A_bar) % q, q)  # nk x m_bar, G W = -A_bar mod q
    S_A = np.block([
        [np.eye(m_bar, dtype=np.int64) + R @ W, R @ S],
        [W, S],
    ])

    gadget_ok = bool(np.all((A @ np.vstack([R, np.eye(nk, dtype=np.int64)])) % q == G % q))
    kernel_ok = bool(np.all((A @ S_A) % q == 0))
    if not (gadget_ok and kernel_ok):
        raise RuntimeError("MP12 TrapGen: gadget relation or kernel relation failed; this should never happen")

    if trace is not None:
        info = mp12_parameters(params, R)
        trace.correction(
            "TrapGen: Micciancio-Peikert gadget trapdoor",
            paper_says="PPSEB uses TrapGen as a black box, citing ABB.",
            we_do=f"MP12: A = [A_bar | G - A_bar R], trapdoor R with entries in [-{r_bound}, {r_bound}], "
                  f"short basis S_A = [[I + RW, RS], [W, S]] (MP12 Lemma 5.3).",
            because="The earlier raw-kernel + LLL construction had no norm guarantee. MP12 is the "
                    "standard way to realize ABB-style trapdoors and bounds the basis norm by "
                    "(s1(R) + 1) * ||S_k~||.",
            algo="TrapGen",
        )
        trace.note(
            "MP12 parameters",
            detail="All widths are Gaussian parameters; std = s / sqrt(2 pi).",
            data={**info, "gs_norm_S_A": gram_schmidt_norm(S_A.astype(float)),
                  "gadget_relation_holds": gadget_ok, "kernel_relation_holds": kernel_ok},
            algo="TrapGen",
        )
    return A, R, S_A


def gadget_sample(v: np.ndarray, q: int, alpha: float, rng: random.Random) -> np.ndarray:
    """z ~ D_{L_v(G), alpha}: short z with G z = v mod q, one k-block per coordinate of v."""
    S_k = gadget_basis_k(q).astype(float)
    k = gadget_k(q)
    blocks = []
    for vi in np.asarray(v, dtype=np.int64) % q:
        t = binary_decompose(np.array([vi]), q)  # particular solution: g^T t = vi
        lattice_point = klein_sample(S_k, -t.astype(float), _std(alpha), rng)
        blocks.append(t + np.asarray(lattice_point, dtype=np.int64))
    z = np.concatenate(blocks)
    assert z.shape == (len(v) * k,)
    return z


def mp12_sample_pre(
    A: np.ndarray, R: np.ndarray, u: np.ndarray, params: Params, rng: random.Random,
    np_rng: np.random.Generator | None = None, trace: Trace | None = None,
) -> np.ndarray:
    """Short x with A x = u mod q, distributed independently of R (MP12 §5.4)."""
    q, m = params.q, params.m
    info = mp12_parameters(params, R)
    alpha, r, s = info["alpha"], info["r"], info["s"]
    nk = R.shape[1]
    T = np.vstack([R, np.eye(nk, dtype=np.int64)]).astype(float)

    # Perturbation p ~ D_{Z^m, sqrt(Sigma_p)} with Sigma_p = s^2 I - alpha^2 T T^T:
    # a continuous Gaussian of covariance (Sigma_p - r^2 I) / (2 pi), then randomized
    # rounding to Z^m at width r (Peikert 2010).
    np_rng = np_rng if np_rng is not None else np.random.default_rng(rng.getrandbits(63))
    cov = (s * s * np.eye(m) - alpha * alpha * (T @ T.T) - r * r * np.eye(m)) / (2 * math.pi)
    L = np.linalg.cholesky(cov)
    y = L @ np_rng.standard_normal(m)
    p = np.array([discrete_gaussian_1d(float(yi), _std(r), rng) for yi in y], dtype=np.int64)

    v = (np.asarray(u, dtype=np.int64) - A @ p) % q
    z = gadget_sample(v, q, alpha, rng)
    x = p + np.vstack([R, np.eye(nk, dtype=np.int64)]) @ z

    ok = bool(np.all((A @ x) % q == np.asarray(u, dtype=np.int64) % q))
    if not ok:
        raise RuntimeError("MP12 SamplePre: A x != u (mod q); this should never happen")
    if trace is not None:
        trace.norm(
            "MP12 SamplePre: preimage",
            detail="x = p + [R; I] z, with perturbation p hiding R and gadget sample z solving G z = u - A p.",
            data={"x_norm": float(np.linalg.norm(x.astype(float))),
                  "norm_bound_s_sqrt_m": info["preimage_norm_bound"], "s": s, "alpha": alpha},
            algo="SamplePre",
        )
    return x
