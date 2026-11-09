"""One config object and one seed (Requirement 10.2, 10.3).

Every randomized operation in MedVault-PQ draws from a seed derived here, and
that seed is written into every result file. Two runs with the same seed and
the same inputs must produce byte-identical output (Property 25), which is what
makes the demo rehearsal trustworthy: if a step prints a different number on
demo day than it did in rehearsal, something is actually different.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

#: The documented project seed. Changing this changes every recorded result.
DEFAULT_SEED = 42

#: Pinned dependency versions are recorded next to this value in result files.
PINNED_VERSIONS = {
    "numpy": ">=1.26,<3",
    "cryptography": ">=42",
    "fastapi": ">=0.110",
    "pydantic": ">=2.6",
    "pytest": ">=8.0",
    "hypothesis": ">=6.98",
}

#: Index modes, in the order they are shown in the UI.
INDEX_MODES = ("A", "B")

#: Default record-set slot size for the PIR database (design decision D4).
DEFAULT_SLOT_SIZE = 4096


def default_data_dir() -> Path:
    """Where blobs, index entries and result files live.

    A single local directory keeps the demo self-contained and makes "clean
    checkout" reproducible: delete the directory and every artefact the system
    produced is gone.
    """
    env = os.environ.get("MEDVAULT_DATA_DIR")
    if env:
        return Path(env)
    return Path(__file__).resolve().parent.parent / "data"


@dataclass
class MedVaultConfig:
    """Everything a MedVault session needs to be deterministic."""

    seed: int = DEFAULT_SEED
    data_dir: Path = field(default_factory=default_data_dir)
    index_mode: str = "B"
    slot_size: int = DEFAULT_SLOT_SIZE
    #: Evil-cloud mode for the blob store: honest | stale | modified | withheld
    evil_mode: str = "honest"
    #: Refuse to write to disk; used by unit tests and by `repro.sh`.
    in_memory: bool = True
    #: Derive DEKs, GCM nonces and index keys from `seed` so two runs agree
    #: byte for byte (Requirement 10.10). A deployment would turn this off.
    deterministic: bool = True
    #: Core unit tests explicitly use the documented signed fallback.
    #: The interactive API selects auto (Groth16 when artifacts are available).
    zk_mode: str = "signed"
    ledger_mode: str = "memory"
    #: Index mode A′: mode A plus the cheap CT2 shape check on entry writes
    #: (deck finding 5's stopgap). Ignored in mode B, which has no PEKS entries.
    ppseb_shape_check: bool = False

    def __post_init__(self) -> None:
        if self.index_mode not in INDEX_MODES:
            raise ValueError(f"index_mode must be one of {INDEX_MODES}, got {self.index_mode!r}")
        if self.slot_size < 1:
            raise ValueError("slot_size must be positive")
        self.data_dir = Path(self.data_dir)

    def sub_seed(self, label: str) -> int:
        """A stable child seed for a named subsystem.

        Deriving seeds by label (rather than incrementing a counter) means the
        order in which subsystems happen to run cannot change anybody's numbers.
        """
        import hashlib

        digest = hashlib.sha256(f"{self.seed}:{label}".encode()).digest()
        return int.from_bytes(digest[:8], "big") % (2**63)

    def ensure_dirs(self) -> None:
        """Create the data directories when persistence is enabled."""
        if self.in_memory:
            return
        for name in ("blobs", "index", "results"):
            (self.data_dir / name).mkdir(parents=True, exist_ok=True)


def library_versions() -> dict[str, str]:
    """Recorded in every result file (Requirement 10.4)."""
    import platform

    out = {"python": platform.python_version()}
    for mod in ("numpy", "cryptography", "hypothesis"):
        try:
            out[mod] = __import__(mod).__version__
        except Exception:  # pragma: no cover - optional dependency
            out[mod] = "not installed"
    return out
