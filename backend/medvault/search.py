"""Search: index modes, keyed tokens, signed one-time authorisation (M3).

Requirements 3. The whole module exists to make one comparison runnable on the
same code path: mode A is the original PPSEB public-tester index, mode B is the
keyed HMAC index. `SearchIndex` is the seam (Requirement 8.2) so an attack
script never branches on the mode — it calls `build`/`search`/`compute_token`
and reports whatever happens.

What each mode actually is
--------------------------
mode A  token = a PEKS trapdoor. The index holds PEKS ciphertexts. `search`
        calls the scheme's public `verify` on every entry. Anyone with the
        public key can build a ciphertext for a guessed keyword and test it
        against a captured trapdoor — that is Finding 1, deliberately retained.
mode B  token = HMAC-SHA-256(K_(doctor, epoch), normalise(keyword)). `search`
        is a byte comparison. Without K the token cannot be recomputed for a
        guess, so the offline dictionary attack has nothing to test against.

Everything else in here — normalisation, commitments, entry signing, nonce
tracking — is mode-independent and is what turns the keyed token into a usable
authorisation scheme rather than just a keyed hash.
"""

from __future__ import annotations

import hashlib
import hmac
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

import numpy as np

from ppseb.params import Params, default_params
from ppseb.scheme import peks_encrypt, trapdoor, verify
from ppseb.trace import Trace

from .crypto import constant_time_equal, sha256


# --------------------------------------------------------------------------
# Keyword tokens
# --------------------------------------------------------------------------

def normalize_keyword(keyword: str) -> str:
    """Lowercase and strip. Idempotent by construction (Requirement 3.1)."""
    return keyword.strip().lower()


def compute_token(index_key: bytes, keyword: str) -> bytes:
    """HMAC-SHA-256(index_key, normalize(keyword)).

    Deterministic for a given (key, keyword): that is what makes re-indexing
    unnecessary and is also the documented linkage leak (Requirement 3.21) —
    the search node can tell two queries for the same keyword apart from two
    queries for different keywords.
    """
    return hmac.new(index_key, normalize_keyword(keyword).encode("utf-8"),
                    hashlib.sha256).digest()


def compute_commitment(token: bytes, nonce: int, epoch: int) -> bytes:
    """The only thing about a search that may reach the chain (Requirement 3.3).

    SHA256(token ‖ nonce ‖ epoch). The token itself never appears on-chain, so a
    chain observer learns that a search happened and how many, not what for.
    """
    return sha256(token, str(nonce).encode("ascii"), str(epoch).encode("ascii"))


# --------------------------------------------------------------------------
# Signed messages
# --------------------------------------------------------------------------

def search_signing_message(token: bytes, nonce: int, epoch: int, timestamp: int) -> bytes:
    """The exact byte string an Ed25519 search signature covers."""
    return (token
            + nonce.to_bytes(8, "big")
            + epoch.to_bytes(4, "big")
            + timestamp.to_bytes(8, "big"))


def entry_signing_message(token: bytes, record_id: str, epoch: int, doctor_id: str) -> bytes:
    """The exact byte string a patient's index-entry signature covers."""
    return (token
            + record_id.encode("utf-8")
            + epoch.to_bytes(4, "big")
            + doctor_id.encode("utf-8"))


def retrieval_signing_message(record_id: str, nonce: int, epoch: int, timestamp: int) -> bytes:
    """The exact byte string an Ed25519 retrieval signature covers.

    Domain-separated from search messages, so a search signature can never be
    presented as a retrieval signature or the other way round.
    """
    return (b"medvault-retrieve-v1"
            + len(record_id.encode("utf-8")).to_bytes(2, "big")
            + record_id.encode("utf-8")
            + nonce.to_bytes(8, "big")
            + epoch.to_bytes(4, "big")
            + timestamp.to_bytes(8, "big"))


def sign_search_request(signing_key, token: bytes, nonce: int, epoch: int,
                        timestamp: int) -> bytes:
    return signing_key.sign(search_signing_message(token, nonce, epoch, timestamp))


def verify_search_signature(verify_key, signature: bytes, token: bytes, nonce: int,
                            epoch: int, timestamp: int) -> bool:
    return verify_key.verify(signature, search_signing_message(token, nonce, epoch, timestamp))


# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------

def pack_array(array: np.ndarray) -> bytes:
    """Serialise an integer matrix for storage in an index entry."""
    return np.ascontiguousarray(array, dtype="<i8").tobytes()


def unpack_array(data: bytes, shape: tuple[int, ...]) -> np.ndarray:
    return np.frombuffer(data, dtype="<i8").reshape(shape).astype(np.int64)


@dataclass(frozen=True)
class IndexEntry:
    """One keyword-token → record-id mapping in a doctor's index."""

    token: bytes
    record_id: str
    epoch: int
    doctor_id: str
    patient_signature: bytes = b""
    #: mode A only: the serialised PEKS ciphertext this entry stands for.
    payload: bytes = b""

    @property
    def signed(self) -> bool:
        return bool(self.patient_signature)

    def public_view(self) -> dict:
        return {
            "token": self.token.hex()[:16],
            "record_id": self.record_id,
            "epoch": self.epoch,
            "doctor_id": self.doctor_id,
            "signed": self.signed,
            "payload_bytes": len(self.payload),
        }


@dataclass
class SearchRequest:
    """A doctor's signed search request."""

    token: bytes
    nonce: int
    epoch: int
    timestamp: int
    signature: bytes
    doctor_id: str
    scope_hash: bytes = b""
    zk_proof: dict | None = None
    #: The keyword, present only on the doctor's side before the token is sent.
    keyword: str = ""


@dataclass
class RetrievalRequest:
    """A doctor's signed request to fetch one record.

    Deck finding 7 is "replay a captured trapdoor, pull the record": signing
    only the search would leave the pull itself replayable, so a retrieval
    carries its own signature and spends a nonce from the same per-doctor
    counter as searches.
    """

    record_id: str
    nonce: int
    epoch: int
    timestamp: int
    signature: bytes
    doctor_id: str


@dataclass
class SearchResult:
    ok: bool
    reason: str
    record_ids: list[str] = field(default_factory=list)
    trace: list[dict] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.ok


# --------------------------------------------------------------------------
# Index modes
# --------------------------------------------------------------------------

class SearchIndex(ABC):
    """One interface, three modes, so attack code never branches on the mode."""

    @abstractmethod
    def build(self, pairs: list[tuple[str, str]], *, index_key: bytes | None,
              epoch: int, doctor_id: str, signing_key=None) -> list[IndexEntry]:
        """Build entries from `(record_id, keyword)` pairs.

        `signing_key` is the patient's Ed25519 key; mode B requires it because
        only patient-signed entries are accepted (Requirement 3.12).
        """

    @abstractmethod
    def search(self, token: bytes, entries: list[IndexEntry]) -> list[str]:
        """Return the record ids matching `token`."""

    @abstractmethod
    def mode_name(self) -> str:
        """'A', 'B', or 'C'."""

    @abstractmethod
    def compute_token(self, index_key: bytes | None, keyword: str) -> bytes:
        """Compute the token a doctor would submit for `keyword`."""

    def describe(self) -> dict:
        return {"mode": self.mode_name(), "class": type(self).__name__}


class ModeBIndex(SearchIndex):
    """Keyed HMAC tokens — the hardened path."""

    def mode_name(self) -> str:
        return "B"

    def build(self, pairs, *, index_key, epoch, doctor_id, signing_key=None) -> list[IndexEntry]:
        if index_key is None:
            raise ValueError("mode B index entries need an index key")
        entries = []
        for record_id, keyword in pairs:
            token = compute_token(index_key, keyword)
            signature = b""
            if signing_key is not None:
                signature = signing_key.sign(
                    entry_signing_message(token, record_id, epoch, doctor_id)
                )
            entries.append(IndexEntry(token, record_id, epoch, doctor_id, signature))
        return entries

    def search(self, token: bytes, entries: list[IndexEntry]) -> list[str]:
        return [e.record_id for e in entries if constant_time_equal(e.token, token)]

    def compute_token(self, index_key, keyword: str) -> bytes:
        if index_key is None:
            raise ValueError("mode B tokens need an index key")
        return compute_token(index_key, keyword)


class ModeAIndex(SearchIndex):
    """Original PPSEB public-tester index — the baseline, kept vulnerable.

    A constructed instance owns the scheme keys because generating a trapdoor is
    what "computing a token" means in this mode. That is the finding: the token
    is derivable from public parameters plus the doctor's basis, and *testing* a
    guess needs no secret at all.
    """

    def __init__(self, params: Params | None = None, *, pk: np.ndarray | None = None,
                 sk: np.ndarray | None = None, mu: np.ndarray | None = None,
                 epoch: int = 0, seed: int = 0) -> None:
        self.params = params or default_params()
        self.pk = pk
        self.sk = sk
        self.mu = mu
        self.epoch = epoch
        self.seed = seed
        self._counter = 0

    def attach_keys(self, pk: np.ndarray, sk: np.ndarray, mu: np.ndarray, *,
                    epoch: int | None = None) -> None:
        """Hand over the scheme keys after construction, for session wiring."""
        self.pk, self.sk, self.mu = pk, sk, mu
        if epoch is not None:
            self.epoch = epoch

    def _rngs(self):
        self._counter += 1
        seed = self.seed + self._counter
        return np.random.default_rng(seed), random.Random(seed)

    def _require_keys(self) -> None:
        if self.pk is None or self.mu is None:
            raise RuntimeError("mode A index has no PPSEB keys attached")

    def mode_name(self) -> str:
        return "A"

    def build(self, pairs, *, index_key, epoch, doctor_id, signing_key=None) -> list[IndexEntry]:
        self._require_keys()
        entries = []
        for record_id, keyword in pairs:
            rng, pyrng = self._rngs()
            ct = peks_encrypt(self.pk, keyword, epoch, self.mu, self.params, rng, pyrng)
            payload = pack_array(ct["CT1"]) + pack_array(ct["CT2"])
            token = sha256(payload)        # the entry's own handle, not a token
            signature = b""
            if signing_key is not None:
                signature = signing_key.sign(
                    entry_signing_message(token, record_id, epoch, doctor_id)
                )
            entries.append(IndexEntry(token, record_id, epoch, doctor_id, signature, payload))
        return entries

    def search(self, token: bytes, entries: list[IndexEntry]) -> list[str]:
        params = self.params
        trap = unpack_array(token, (params.m,))
        hits = []
        for entry in entries:
            if not entry.payload:
                continue
            ct1 = unpack_array(entry.payload[: 8 * params.l], (params.l,))
            ct2 = unpack_array(entry.payload[8 * params.l:], (params.m, params.l))
            match, _y = verify(ct1, ct2, trap, params)
            if match:
                hits.append(entry.record_id)
        return hits

    def compute_token(self, index_key, keyword: str) -> bytes:
        self._require_keys()
        if self.sk is None:
            raise RuntimeError("mode A needs the doctor's basis to build a trapdoor")
        _rng, pyrng = self._rngs()
        trap = trapdoor(self.pk, self.sk, keyword, self.epoch, self.mu, self.params, pyrng)
        return pack_array(trap)

    def universal_plant(self, epoch: int, doctor_id: str) -> IndexEntry:
        """The Finding 2 ciphertext: `CT1 = ⌊q/2⌋`, `CT2 = 0`.

        `verify` computes `y = CT1 - Trap·CT2 = ⌊q/2⌋`, and every coefficient
        sits exactly on the accept point, so this entry matches every search.
        It exists so the plant attack has something concrete to plant.
        """
        params = self.params
        ct1 = np.full((params.l,), params.q // 2, dtype=np.int64)
        ct2 = np.zeros((params.m, params.l), dtype=np.int64)
        payload = pack_array(ct1) + pack_array(ct2)
        return IndexEntry(sha256(payload), "PLANTED", epoch, doctor_id, b"", payload)


# --------------------------------------------------------------------------
# Search node
# --------------------------------------------------------------------------

class SearchNode:
    """Holds per-doctor per-epoch indexes and validates entry writes.

    `require_patient_signature` is the whole mode difference on the write side.
    Mode A runs with it *off* because PPSEB has no such check — that is Finding
    2, and the demo's job is to show the plant succeeding there and being
    rejected in mode B, where it is on.
    """

    def __init__(self, *, require_patient_signature: bool = True,
                 shape_check_params: Params | None = None) -> None:
        self.require_patient_signature = require_patient_signature
        #: Mode A′: when set, PEKS payloads must pass `check_ciphertext_shape`.
        self.shape_check_params = shape_check_params
        # index[doctor_id][epoch] = list[IndexEntry]
        self._index: dict[str, dict[int, list[IndexEntry]]] = {}
        # owner[doctor_id][epoch] = patient_id
        self._owner: dict[str, dict[int, str]] = {}
        #: Rejections, so the auditor view can show what was refused and why.
        self.rejected: list[dict] = []
        self._patient_keys: dict[str, object] = {}

    def trust_patient(self, patient_id: str, verify_key) -> None:
        """Patient provisioning boundary; not part of the untrusted write API."""
        existing = self._patient_keys.get(patient_id)
        if existing is not None and existing.public_bytes != verify_key.public_bytes:
            raise ValueError("patient key replacement requires explicit reprovisioning")
        self._patient_keys[patient_id] = verify_key

    def remove_records(self, doctor_id: str, epoch: int, record_ids: list[str]) -> None:
        entries = self._index.get(doctor_id, {}).get(epoch, [])
        removed = set(record_ids)
        self._index.setdefault(doctor_id, {})[epoch] = [
            entry for entry in entries if entry.record_id not in removed]

    # -- writes -----------------------------------------------------------
    def add_entry(self, entry: IndexEntry, patient_verify_key, patient_id: str
                  ) -> tuple[bool, str]:
        """Add an entry; returns `(accepted, reason)`.

        Accepts only entries signed by the patient who owns that doctor's index
        for that epoch (Requirement 3.11/3.12).
        """
        owner = self._owner.get(entry.doctor_id, {}).get(entry.epoch)
        if self.require_patient_signature:
            if not entry.signed:
                return self._reject(entry, "unsigned_entry")
            message = entry_signing_message(entry.token, entry.record_id,
                                            entry.epoch, entry.doctor_id)
            trusted = self._patient_keys.get(patient_id)
            # Ignore the caller-provided key: only a provisioned patient may sign.
            if trusted is None or not trusted.verify(entry.patient_signature, message):
                return self._reject(entry, "bad_entry_signature")
            if owner is not None and owner != patient_id:
                return self._reject(entry, "foreign_entry")

        if self.shape_check_params is not None and entry.payload:
            from .wellformed import check_ciphertext_shape  # avoid an import cycle

            p = self.shape_check_params
            ct1 = unpack_array(entry.payload[: 8 * p.l], (p.l,))
            ct2 = unpack_array(entry.payload[8 * p.l:], (p.m, p.l))
            verdict = check_ciphertext_shape(ct1, ct2, p)
            if not verdict.ok:
                return self._reject(entry, "malformed_ciphertext")

        self._owner.setdefault(entry.doctor_id, {}).setdefault(entry.epoch, patient_id)
        self._index.setdefault(entry.doctor_id, {}).setdefault(entry.epoch, []).append(entry)
        return True, "accepted"

    def add_entries(self, entries: list[IndexEntry], patient_verify_key, patient_id: str
                    ) -> tuple[list[IndexEntry], list[dict]]:
        accepted, rejected = [], []
        for entry in entries:
            ok, reason = self.add_entry(entry, patient_verify_key, patient_id)
            if ok:
                accepted.append(entry)
            else:
                rejected.append({"record_id": entry.record_id, "reason": reason})
        return accepted, rejected

    def _reject(self, entry: IndexEntry, reason: str) -> tuple[bool, str]:
        self.rejected.append({"doctor_id": entry.doctor_id, "record_id": entry.record_id,
                              "reason": reason})
        return False, reason

    # -- reads ------------------------------------------------------------
    def entries(self, doctor_id: str, epoch: int) -> list[IndexEntry]:
        return list(self._index.get(doctor_id, {}).get(epoch, []))

    def search(self, token: bytes, doctor_id: str, epoch: int,
               index: SearchIndex) -> list[str]:
        """Search one doctor's index for one epoch. No cross-doctor leakage."""
        entries = self.entries(doctor_id, epoch)
        return sorted(set(index.search(token, entries)))

    def epoch_count(self, doctor_id: str) -> int:
        return len(self._index.get(doctor_id, {}))

    def total_entries(self) -> int:
        return sum(len(entries)
                   for per_epoch in self._index.values()
                   for entries in per_epoch.values())

    def snapshot_for_audit(self, doctor_id: str | None = None) -> dict:
        """A token-free summary — what an auditor may see (Requirement 15.4)."""
        if doctor_id is not None:
            per_epoch = {str(e): [x.public_view() for x in entries]
                         for e, entries in self._index.get(doctor_id, {}).items()}
            return {"doctor_id": doctor_id, "epochs": per_epoch}
        return {
            "doctors": {
                doctor: {str(e): len(entries) for e, entries in per_epoch.items()}
                for doctor, per_epoch in self._index.items()
            },
            "total_entries": self.total_entries(),
            "rejected": list(self.rejected),
        }

    def drop_epochs_below(self, doctor_id: str, epoch: int) -> int:
        """Erase index epochs older than `epoch` after a rotation.

        Returns the number of entries dropped, which is one of the measured
        re-indexing costs (Requirement 4.9).
        """
        per_epoch = self._index.get(doctor_id, {})
        stale = [e for e in per_epoch if e < epoch]
        dropped = sum(len(per_epoch[e]) for e in stale)
        for e in stale:
            del per_epoch[e]
        return dropped


def build_mode(mode: str, trace: Trace | None = None, **kwargs) -> SearchIndex:
    """Construct the index for a mode letter."""
    if mode == "A":
        index = ModeAIndex(**kwargs)
    elif mode == "B":
        index = ModeBIndex()
    elif mode == "C":
        raise NotImplementedError(
            "mode C (PAEKS) is P1 per design decision D3 and is not built yet"
        )
    else:
        raise ValueError(f"unknown index mode {mode!r}")
    if trace is not None:
        trace.note(
            f"Index mode {mode}",
            detail={
                "A": "public-tester PPSEB: the token is a trapdoor and any ciphertext "
                     "can be tested against it, so offline keyword guessing works",
                "B": "keyed HMAC: without the per-doctor per-epoch key a guess cannot "
                     "even be turned into a token",
            }.get(mode, ""),
            data={"mode": mode, "allowed_compare": "mode A vs mode B"},
            algo="SearchIndex",
            highlight=True,
        )
    return index
