"""M5 — private retrieval with single-server LWE PIR (SimplePIR shape).

Requirement 5. The storage server holds the record ciphertexts as fixed-size
slots in a matrix and answers a query without learning which slot was asked
for. The construction is SimplePIR (Henzinger, Hong, Corrigan-Gibbs, Meiklejohn,
Vaikuntanathan, USENIX Security 2023), written out in numpy:

    D  : rows x slot_size, one byte per entry          (the database)
    A  : rows x n, uniform mod q, expanded from a seed (public)
    H  = D^T A          : slot_size x n                (the hint, sent once)
    qu = A s + e + Delta * u_i                         (the query, rows entries)
    an = D^T qu         : slot_size entries            (the answer)
    an - H s = D^T e + Delta * D[i]  -> round by Delta -> slot i

with q = 2^32 (numpy uint32 arithmetic wraps, which *is* reduction mod q),
plaintext modulus p = 256 (one byte per entry) and Delta = q / p.

Why the server learns nothing about `i`: the query is `A s + e` plus a single
scaled unit vector, i.e. an LWE sample, and without `s` it is indistinguishable
from uniform. Its size is `rows * 4` bytes for every index (Property 17) and the
server's log records sizes and times only (Property 19, Requirement 5.5).

What it does not hide, stated where the code is (Requirements 5.6, 5.7):
  * PIR hides retrieval from the *storage server* only. The search node still
    sees which record ids matched a token.
  * If the storage server and the search node collude, the matched ids give the
    index away. They must not collude; nothing here prevents it.

Parameters are the SimplePIR ones (n = 1024, q = 2^32, sigma = 6.4) and every
measurement is labelled with them (Requirement 12.10). They are not tuned for a
security level beyond what that paper states, and this implementation is
non-constant-time numpy, not a hardened library.
"""

from __future__ import annotations

import os
import random
import struct
import time
from dataclasses import dataclass, field

import numpy as np

#: SimplePIR parameter set (USENIX Security 2023, Table 2 regime).
DEFAULT_LWE_DIM = 1024
MODULUS_BITS = 32
MODULUS = 2 ** MODULUS_BITS
PLAINTEXT_BITS = 8
PLAINTEXT_MODULUS = 2 ** PLAINTEXT_BITS
DELTA = MODULUS // PLAINTEXT_MODULUS
NOISE_SIGMA = 6.4

#: Bytes of slot header: record version (u32) and ciphertext length (u32).
SLOT_HEADER = 8

#: Decision D4: the database is capped so the demo answers in well under a
#: second. Anything above the cap is refused rather than silently truncated.
MAX_DB_ROWS = 1024

#: PIR slot size used by the demo world. Records in the demo are a few hundred
#: bytes; 512 keeps the hint at 2 MiB (`slot_size * n * 4`).
DEMO_SLOT_SIZE = 512


class PIRError(ValueError):
    """A slot that does not fit, a database over the cap, or a bad state blob."""


@dataclass(frozen=True)
class PIRParams:
    db_rows: int
    slot_size: int
    lwe_dim: int = DEFAULT_LWE_DIM
    modulus: int = MODULUS

    def __post_init__(self) -> None:
        if self.modulus != MODULUS:
            raise PIRError("this implementation needs q = 2^32 (uint32 wrap-around)")
        if not 1 <= self.db_rows <= MAX_DB_ROWS:
            raise PIRError(f"db_rows must be in [1, {MAX_DB_ROWS}] (D4 cap), got {self.db_rows}")
        if self.lwe_dim < 1:
            raise PIRError("lwe_dim must be positive")
        if self.slot_size <= SLOT_HEADER:
            raise PIRError(f"slot_size must exceed the {SLOT_HEADER}-byte header")

    def label(self) -> dict:
        """The lattice parameters printed next to every PIR number (R12.10)."""
        return {"n": self.lwe_dim, "q": f"2^{MODULUS_BITS}", "p": PLAINTEXT_MODULUS,
                "sigma": NOISE_SIGMA, "db_rows": self.db_rows, "slot_size": self.slot_size}


@dataclass
class PIRHint:
    """Everything the client holds before querying.

    `A` is public and in a real deployment is expanded from `a_seed` on both
    sides; it is kept materialised here because the client needs `A s`.
    `H = D^T A` is the SimplePIR hint the server publishes after setup.
    """

    A: np.ndarray
    H: np.ndarray
    a_seed: int
    params: PIRParams

    def size_bytes(self) -> int:
        # The client downloads H; A is regenerated from the seed.
        return int(self.H.nbytes) + 8


@dataclass
class PIRQuery:
    """`query` goes to the server. `state` never leaves the client."""

    query: np.ndarray
    state: bytes = field(repr=False)

    def size_bytes(self) -> int:
        return int(self.query.nbytes)


@dataclass
class PIRAnswer:
    answer: np.ndarray

    def size_bytes(self) -> int:
        return int(self.answer.nbytes)


@dataclass
class PIRMeasurement:
    hint_size: int
    query_size: int
    answer_size: int
    server_time_ms: float
    db_size: int
    setup_time_ms: float = 0.0
    client_time_ms: float = 0.0
    params: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "db_size": self.db_size,
            "hint_bytes": self.hint_size,
            "query_bytes": self.query_size,
            "answer_bytes": self.answer_size,
            "server_time_ms": round(self.server_time_ms, 3),
            "setup_time_ms": round(self.setup_time_ms, 3),
            "client_time_ms": round(self.client_time_ms, 3),
            "params": self.params,
        }


# --------------------------------------------------------------------------
# Slot packing
# --------------------------------------------------------------------------

def pack_slot(payload: bytes, version: int, slot_size: int) -> bytes:
    """`version ‖ len ‖ payload`, zero-padded to `slot_size`."""
    if len(payload) > slot_size - SLOT_HEADER:
        raise PIRError(f"payload of {len(payload)} bytes does not fit a {slot_size}-byte slot")
    head = struct.pack(">II", version, len(payload))
    return (head + payload).ljust(slot_size, b"\x00")


def unpack_slot(slot: bytes) -> tuple[int, bytes]:
    """Inverse of `pack_slot`. An all-zero slot unpacks to `(0, b"")`."""
    if len(slot) < SLOT_HEADER:
        raise PIRError("slot is shorter than its header")
    version, length = struct.unpack(">II", slot[:SLOT_HEADER])
    if length > len(slot) - SLOT_HEADER:
        raise PIRError("slot length field exceeds the slot")
    return version, slot[SLOT_HEADER:SLOT_HEADER + length]


def build_database(slots: list[bytes], slot_size: int) -> np.ndarray:
    """Stack fixed-size slots into the `rows x slot_size` uint32 matrix."""
    if not slots:
        raise PIRError("the PIR database needs at least one slot")
    out = np.zeros((len(slots), slot_size), dtype=np.uint32)
    for i, slot in enumerate(slots):
        if len(slot) != slot_size:
            raise PIRError(f"slot {i} is {len(slot)} bytes, expected {slot_size}")
        out[i] = np.frombuffer(slot, dtype=np.uint8)
    return out


# --------------------------------------------------------------------------
# The protocol
# --------------------------------------------------------------------------

def _rng(rng) -> np.random.Generator:
    if isinstance(rng, np.random.Generator):
        return rng
    return np.random.default_rng(rng)


def _expand_a(a_seed: int, rows: int, n: int) -> np.ndarray:
    return np.random.default_rng(a_seed).integers(0, MODULUS, size=(rows, n), dtype=np.uint32)


def _encode_state(secret: np.ndarray, index: int) -> bytes:
    return struct.pack(">I", index) + secret.astype("<u4").tobytes()


def _decode_state(state: bytes, n: int) -> tuple[np.ndarray, int]:
    if len(state) != 4 + 4 * n:
        raise PIRError("client state has the wrong length for this hint")
    index = struct.unpack(">I", state[:4])[0]
    secret = np.frombuffer(state[4:], dtype="<u4").astype(np.uint32)
    return secret, index


class PIRServer:
    """SimplePIR-style single-server LWE PIR.

    The client half (`client_query`, `reconstruct`) lives on this class too,
    because the design keeps one interface; the methods that model the server
    (`setup`, `answer`) never receive the client state, and only they write to
    `log`.
    """

    def __init__(self) -> None:
        #: The storage server's own view. Sizes and timings only — no index.
        self.log: list[dict] = []

    # -- server ------------------------------------------------------------
    def setup(self, database: np.ndarray, params: PIRParams, rng) -> PIRHint:
        """Draw the public matrix A and publish the hint H = D^T A."""
        if database.shape != (params.db_rows, params.slot_size):
            raise PIRError(f"database shape {database.shape} does not match params "
                           f"({params.db_rows}, {params.slot_size})")
        a_seed = int(_rng(rng).integers(0, 2 ** 63))
        A = _expand_a(a_seed, params.db_rows, params.lwe_dim)
        started = time.perf_counter()
        H = database.T @ A
        self.log.append({"event": "setup", "db_rows": params.db_rows,
                         "slot_size": params.slot_size,
                         "hint_bytes": int(H.nbytes),
                         "ms": round((time.perf_counter() - started) * 1000.0, 3)})
        return PIRHint(A=A, H=H, a_seed=a_seed, params=params)

    def answer(self, database: np.ndarray, query: np.ndarray, params: PIRParams) -> np.ndarray:
        """`D^T qu`. The server multiplies; it never sees which row it selected."""
        if query.shape != (params.db_rows,) or query.dtype != np.uint32:
            raise PIRError("query must be a uint32 vector with one entry per row")
        started = time.perf_counter()
        out = database.T @ query
        self.log.append({"event": "answer", "query_bytes": int(query.nbytes),
                         "answer_bytes": int(out.nbytes),
                         "ms": round((time.perf_counter() - started) * 1000.0, 3)})
        return out

    # -- client ------------------------------------------------------------
    def client_query(self, index: int, params: PIRParams, hint: PIRHint, rng=None) -> PIRQuery:
        if not 0 <= index < params.db_rows:
            raise PIRError(f"index {index} outside [0, {params.db_rows})")
        if hint.params != params:
            raise PIRError("hint parameters do not match the query")
        if rng is None:
            # Production-facing queries use OS entropy, not numpy's public seed.
            secret = np.frombuffer(os.urandom(4 * params.lwe_dim), dtype="<u4").copy()
            secure = random.SystemRandom()
            noise = np.array([round(secure.gauss(0, NOISE_SIGMA))
                              for _ in range(params.db_rows)], dtype=np.int64)
        else:
            # Explicit seeded RNG is for reproducible protocol tests only.
            gen = _rng(rng)
            secret = gen.integers(0, MODULUS, size=params.lwe_dim, dtype=np.uint32)
            noise = np.rint(gen.normal(0.0, NOISE_SIGMA, size=params.db_rows)).astype(np.int64)
        query = hint.A @ secret
        query = query + noise.astype(np.uint32)          # wraps: negative noise mod q
        query[index] = np.uint32((int(query[index]) + DELTA) % MODULUS)
        return PIRQuery(query=query.astype(np.uint32), state=_encode_state(secret, index))

    def reconstruct(self, answer: np.ndarray, state: bytes, params: PIRParams,
                    hint: PIRHint) -> bytes:
        if answer.shape != (params.slot_size,) or answer.dtype != np.uint32:
            raise PIRError("answer must be a uint32 vector of slot_size entries")
        secret, _index = _decode_state(state, params.lwe_dim)
        noisy = answer - hint.H @ secret                 # = Delta * D[i] + D^T e (mod q)
        rounded = ((noisy.astype(np.uint64) + DELTA // 2) // DELTA) % PLAINTEXT_MODULUS
        return rounded.astype(np.uint8).tobytes()

    # -- measurement -------------------------------------------------------
    def measure(self, database: np.ndarray, params: PIRParams, hint: PIRHint | None,
                rng, *, index: int = 0) -> PIRMeasurement:
        """One full round trip; sizes in bytes, times in ms (R5.3, R12.7)."""
        gen = _rng(rng)
        setup_ms = 0.0
        if hint is None:
            started = time.perf_counter()
            hint = self.setup(database, params, gen)
            setup_ms = (time.perf_counter() - started) * 1000.0
        started = time.perf_counter()
        query = self.client_query(index, params, hint, gen)
        client_ms = (time.perf_counter() - started) * 1000.0
        started = time.perf_counter()
        answer = self.answer(database, query.query, params)
        server_ms = (time.perf_counter() - started) * 1000.0
        started = time.perf_counter()
        slot = self.reconstruct(answer, query.state, params, hint)
        client_ms += (time.perf_counter() - started) * 1000.0
        if slot != database[index].astype(np.uint8).tobytes():
            raise PIRError("PIR round trip did not reproduce the stored slot")
        return PIRMeasurement(
            hint_size=hint.size_bytes(), query_size=query.size_bytes(),
            answer_size=int(answer.nbytes), server_time_ms=server_ms,
            db_size=params.db_rows, setup_time_ms=setup_ms, client_time_ms=client_ms,
            params=params.label(),
        )


# --------------------------------------------------------------------------
# The storage server as the demo world sees it
# --------------------------------------------------------------------------

class PIRStore:
    """The cloud's PIR front end over one patient's record slots.

    The cloud already holds the slot directory; the chain contains only a root,
    not record IDs. Directory metadata is distributed off-chain by the patient.
    `fetch` is a client-side convenience; only its encrypted query goes to the
    server's `answer` method. This in-process prototype is not process isolation.
    """

    def __init__(self, slot_size: int = DEMO_SLOT_SIZE, lwe_dim: int = DEFAULT_LWE_DIM,
                 seed: int = 0) -> None:
        self.slot_size = slot_size
        self.lwe_dim = lwe_dim
        self._rng = np.random.default_rng(seed)
        self.server = PIRServer()
        self.directory: list[str] = []
        self.database: np.ndarray | None = None
        self.params: PIRParams | None = None
        self.hint: PIRHint | None = None
        self._fingerprint: tuple | None = None

    def load(self, rows: list[tuple[str, int, bytes | None]]) -> bool:
        """(Re)build from the cloud's served view; returns True if rebuilt.

        `rows` is `(record_id, version, ciphertext_or_None)` in directory order.
        A withheld record becomes an all-zero slot, which the client reads as
        "nothing served" — the server simply has nothing to give.
        """
        import hashlib
        fingerprint = tuple((rid, v, None if ct is None else hashlib.sha256(ct).digest())
                            for rid, v, ct in rows)
        if fingerprint == self._fingerprint and self.hint is not None:
            return False
        self.directory = [rid for rid, _, _ in rows]
        slots = [b"\x00" * self.slot_size if ct is None else pack_slot(ct, v, self.slot_size)
                 for _, v, ct in rows]
        self.database = build_database(slots, self.slot_size)
        self.params = PIRParams(db_rows=len(slots), slot_size=self.slot_size,
                                lwe_dim=self.lwe_dim)
        self.hint = self.server.setup(self.database, self.params, self._rng)
        self._fingerprint = fingerprint
        return True

    def fetch(self, row: int, rng=None) -> tuple[int, bytes, dict]:
        """Client-side fetch of one row; returns `(version, payload, sizes)`."""
        if self.database is None or self.params is None or self.hint is None:
            raise PIRError("PIR store has not been loaded")
        query = self.server.client_query(row, self.params, self.hint, rng)
        started = time.perf_counter()
        answer = self.server.answer(self.database, query.query, self.params)
        server_ms = (time.perf_counter() - started) * 1000.0
        slot = self.server.reconstruct(answer, query.state, self.params, self.hint)
        version, payload = unpack_slot(slot)
        sizes = {"hint_bytes": self.hint.size_bytes(), "query_bytes": query.size_bytes(),
                 "answer_bytes": int(answer.nbytes), "server_ms": round(server_ms, 3),
                 "db_rows": self.params.db_rows, "params": self.params.label()}
        return version, payload, sizes


def measure_pir(db_sizes: tuple[int, ...] = (16, 256), slot_size: int = DEMO_SLOT_SIZE,
                seed: int = 0, lwe_dim: int = DEFAULT_LWE_DIM) -> list[dict]:
    """Requirement 5.3 / 12.7: sizes and server time against database size."""
    rng = np.random.default_rng(seed)
    out = []
    for rows in db_sizes:
        params = PIRParams(db_rows=rows, slot_size=slot_size, lwe_dim=lwe_dim)
        database = rng.integers(0, 256, size=(rows, slot_size), dtype=np.uint32)
        server = PIRServer()
        out.append(server.measure(database, params, None, rng, index=rows // 2).as_dict())
    return out
