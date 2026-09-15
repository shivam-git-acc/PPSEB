"""Parameter sets for the PPSEB lab.

Real lattice-crypto parameters (n in the hundreds, q huge) make every matrix
opaque and every run slow. This lab runs at deliberately tiny parameters so
the UI can show *every* matrix and every step, live, in under two seconds.
The trade-off (spelled out in CLAUDE.md §2) is explicit and configurable —
nothing here is a hidden shortcut.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field


def is_prime(k: int) -> bool:
    if k < 2:
        return False
    if k in (2, 3):
        return True
    if k % 2 == 0:
        return False
    i = 3
    while i * i <= k:
        if k % i == 0:
            return False
        i += 2
    return True


@dataclass
class Params:
    """A parameter set for the scheme.

    n     : lattice dimension (rows of A / pk)
    q     : prime modulus
    m     : number of columns; derived unless explicitly overridden
    sigma : Gaussian width used by SamplePre / SampleGaussian / NewBasisDel
    l     : keyword-test length ("security level" S_l in the paper) — the
            width of the shared matrix B_j and of CT1 / CT2.
    usability_C : the smoothing-constant modelling choice used by
            attacks.forward_sec.usability_threshold (Finding 2, PATCH 02
            §A.2) — exposed here (not hardcoded in the attack module) so the
            UI can show and, if desired, vary it. Default 0.2: the textbook
            asymptotic constant (1.0) is strict enough to reject even a
            freshly-generated TrapGen root basis at these toy parameters
            (Lemma 1 in the paper claims O(sqrt(n log q)) ~ 6 for that root
            basis), which would make the threshold degenerate before any
            KeyExt is even invoked. See usability_threshold's own docstring
            for the full derivation and the C=1 comparison it also reports.
    ciphertext_noise_sigma : the noise width scheme.py adds to PEKS/record
            ciphertexts (CT1/CT2/Trap's inner product, and the record PKE) —
            a DIFFERENT width from `sigma` above (that one governs lattice
            SAMPLING quality; this one governs Verify's decode margin).
            Exposed here (not a hardcoded scheme.py constant) because PATCH
            05's end-to-end attack discovered they interact: PATCH 03's
            dimension-aware sigma (needed for NewBasisDel's own correctness)
            makes Trap's own norm grow too, which — at a FIXED ciphertext
            noise width — can blow Verify's decode margin and break even the
            LEGITIMATE doctor's search. attacks.end_to_end scales this field
            down in proportion to how far sigma was scaled up, preserving
            the original, already-tuned margin rather than fixing one bound
            by breaking another.
    """

    n: int = 4
    q: int = 257
    sigma: float = 4.0
    l: int = 10
    usability_C: float = 0.2
    ciphertext_noise_sigma: float = 0.4
    m: int = field(default=0)  # 0 => "derive it"

    def __post_init__(self) -> None:
        if self.m == 0:
            self.m = derived_m(self.n, self.q)

    # -- validation -------------------------------------------------------
    def validate(self) -> list[str]:
        """Return a list of human-readable violations (empty = valid)."""
        problems: list[str] = []
        if not is_prime(self.q):
            problems.append(f"q={self.q} is not prime; the modulus must be a prime.")
        min_m = derived_m(self.n, self.q)
        if self.m < min_m:
            problems.append(
                f"m={self.m} is too small; need m >= 2*n*ceil(log2 q) = {min_m}."
            )
        if self.n < 2:
            problems.append("n must be >= 2.")
        if self.sigma <= 0:
            problems.append("sigma must be positive.")
        if self.l < 1:
            problems.append("l must be >= 1.")
        if self.usability_C <= 0:
            problems.append("usability_C must be positive.")
        if self.ciphertext_noise_sigma <= 0:
            problems.append("ciphertext_noise_sigma must be positive.")
        if self.m % self.n != 0:
            problems.append(
                f"m={self.m} is not a multiple of n={self.n}; H2's block-diagonal "
                "FRD construction (§3.4) requires n | m."
            )
        return problems

    @property
    def log2q(self) -> int:
        return math.ceil(math.log2(self.q))

    def shape_table(self) -> dict:
        """The 'type discipline' table emitted once at init (CLAUDE.md §3.1)."""
        return {
            "pk_r": f"Z_q^{{{self.n}x{self.m}}}",
            "sk_r": f"Z^{{{self.m}x{self.m}}} (short basis of L_perp(pk_r))",
            "mu": f"Z_q^{{{self.n}}}",
            "B_j": f"Z_q^{{{self.n}x{self.l}}} (SHARED between CT1, CT2)",
            "CT_j1": f"Z_q^{{1x{self.l}}}",
            "CT_j2": f"Z_q^{{{self.m}x{self.l}}}",
            "Trap": f"Z_q^{{{self.m}}}",
            "R = H1(pk,j)": f"Z_q^{{{self.m}x{self.m}}} (I + low-norm nilpotent N)",
            "beta = H2(w,j)": f"Z_q^{{{self.m}x{self.m}}} (FRD; differences invertible)",
        }


def derived_m(n: int, q: int) -> int:
    return 2 * n * math.ceil(math.log2(q))


def default_params() -> Params:
    return Params(n=4, q=257, sigma=4.0, l=10)
