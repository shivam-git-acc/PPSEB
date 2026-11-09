"""Content-addressed ciphertext storage with a switchable "evil cloud" mode.

Requirements 1.2-1.5. The store keeps every version of every record, because
the interesting attack is not "the cloud corrupted a blob" but "the cloud
served you last week's blob and called it today's". Keeping history is what
makes that attack reproducible on demand instead of hypothetical.

The evil modes are the demonstrator's control, not a security feature: they let
the audit step show a detection working, with the honest mode as the control
otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .crypto import RandomSource, aes_gcm_decrypt, aes_gcm_encrypt, new_dek, sha256

EVIL_MODES = ("honest", "stale", "modified", "withheld")


@dataclass(frozen=True)
class StoredBlob:
    """One immutable version of one record's ciphertext."""

    record_id: str
    content_hash: str          # SHA-256 hex of (record_id ‖ ciphertext)
    ciphertext: bytes          # AES-256-GCM sealed blob (nonce ‖ data ‖ tag)
    version: int
    patient_id: str

    def as_public_dict(self) -> dict:
        """Everything the UI may show: no key material, no plaintext."""
        return {
            "record_id": self.record_id,
            "content_hash": self.content_hash,
            "version": self.version,
            "size_bytes": len(self.ciphertext),
        }


@dataclass
class BlobResult:
    """What the store handed back, and whether it was honest about it."""

    ok: bool
    reason: str                    # honest | stale | modified | withheld | not_found
    blob: StoredBlob | None = None
    #: The hash of the bytes actually served, recomputed by the store. The
    #: retrieval path re-derives it rather than trusting this field.
    served_hash: str = ""


@dataclass
class PutResult:
    """What a `put` produced, including the DEK the caller must wrap."""

    record_id: str
    content_hash: str
    version: int
    dek: bytes
    size_bytes: int


@dataclass
class PatientRecordStore:
    """All versions of all records for one patient, keyed by record id.

    Two version numbers, deliberately distinct:
      * a record's own version counts rewrites of *that* record, and is what a
        retrieval compares against to catch a stale blob;
      * `snapshot_version` counts commits of the whole record set, and is the
        number committed on-chain alongside the Merkle root. Without the
        distinction, adding a new record would make every older record look
        stale - which would be a bug wearing a security label.
    """

    records: dict[str, list[StoredBlob]] = field(default_factory=dict)
    snapshot_version: int = 0

    def latest(self, record_id: str) -> StoredBlob | None:
        versions = self.records.get(record_id)
        return versions[-1] if versions else None

    def current_version(self, record_id: str) -> int:
        versions = self.records.get(record_id)
        return versions[-1].version if versions else 0

    def record_ids(self) -> list[str]:
        return sorted(self.records)


class BlobStore:
    """The ciphertext store every other module talks to.

    One instance holds many patients (the demo has one, the tests have several,
    and the "foreign entry" test needs at least two).
    """

    def __init__(self, random_source: RandomSource | None = None) -> None:
        self._patients: dict[str, PatientRecordStore] = {}
        self._evil_mode: str = "honest"
        #: Optional deterministic source for the DEK and the GCM nonce. When it
        #: is None, both come from the OS CSPRNG — the safe default.
        self._random = random_source
        #: Every get() is appended here, so a test can inspect the server's
        #: view exactly as a log-inspection test would (Requirement 5.5 shape).
        self.access_log: list[dict] = []

    # -- configuration ----------------------------------------------------
    def set_evil_mode(self, mode: str) -> None:
        if mode not in EVIL_MODES:
            raise ValueError(f"evil mode must be one of {EVIL_MODES}, got {mode!r}")
        self._evil_mode = mode

    @property
    def evil_mode(self) -> str:
        return self._evil_mode

    # -- writes -----------------------------------------------------------
    def store(self, record_id: str, plaintext: bytes, *, patient_id: str,
              dek: bytes | None = None) -> PutResult:
        """Encrypt under a fresh DEK (unless one is supplied) and store it."""
        patient = self._patients.setdefault(patient_id, PatientRecordStore())
        dek = dek if dek is not None else new_dek(self._random)
        nonce = self._random.random_bytes(12) if self._random is not None else None
        ciphertext = aes_gcm_encrypt(dek, plaintext, nonce=nonce)
        content_hash = sha256(record_id.encode("utf-8"), ciphertext).hex()
        versions = patient.records.setdefault(record_id, [])
        version = len(versions) + 1
        versions.append(StoredBlob(record_id, content_hash, ciphertext, version, patient_id))
        return PutResult(record_id, content_hash, version, dek, len(ciphertext))

    def put(self, record_id: str, plaintext: bytes, *,
            patient_id: str = "patient") -> PutResult:
        """`store` with the default patient, for short call sites."""
        return self.store(record_id, plaintext, patient_id=patient_id)

    # -- reads ------------------------------------------------------------
    def bump_snapshot(self, patient_id: str) -> int:
        """Advance the whole-record-set version committed on-chain."""
        patient = self._patients.setdefault(patient_id, PatientRecordStore())
        patient.snapshot_version += 1
        return patient.snapshot_version

    def latest_version(self, patient_id: str) -> int:
        """The snapshot version last committed for this patient."""
        return self._patients.get(patient_id, PatientRecordStore()).snapshot_version

    def record_version(self, patient_id: str, record_id: str) -> int:
        patient = self._patients.get(patient_id)
        return patient.current_version(record_id) if patient else 0

    def head(self, patient_id: str, record_id: str) -> StoredBlob | None:
        """The newest stored version, without applying any evil mode."""
        patient = self._patients.get(patient_id)
        return patient.latest(record_id) if patient else None

    def get(self, patient_id: str, record_id: str, *, expected_version: int | None = None
            ) -> BlobResult:
        """Serve a blob, applying the current evil-cloud mode.

        `expected_version` is the record version the caller believes is current;
        the stale mode needs it to know what "older" means. It defaults to the
        record's own latest version.
        """
        patient = self._patients.get(patient_id)
        versions = patient.records.get(record_id) if patient else None
        if not versions:
            self.access_log.append({"patient": patient_id, "record_id": record_id,
                                    "served": "not_found"})
            return BlobResult(ok=False, reason="not_found")

        result, served_label = self._serve(versions, expected_version)
        self.access_log.append({"patient": patient_id, "record_id": record_id,
                                "served": served_label})
        return result

    def _serve(self, versions: list[StoredBlob], expected_version: int | None
               ) -> tuple[BlobResult, str]:
        """Apply the evil-cloud mode to one record's version history."""
        current = versions[-1]
        record_id = current.record_id
        if expected_version is None:
            expected_version = current.version

        if self._evil_mode == "withheld":
            return BlobResult(ok=False, reason="withheld"), "withheld"

        if self._evil_mode == "stale":
            older = [b for b in versions if b.version < expected_version]
            served = older[0] if older else StoredBlob(
                current.record_id, current.content_hash, current.ciphertext,
                max(expected_version - 1, 0), current.patient_id,
            )
            return (BlobResult(ok=True, reason="stale", blob=served,
                               served_hash=sha256(record_id.encode(), served.ciphertext).hex()),
                    f"stale v{served.version}")

        if self._evil_mode == "modified":
            served = self._flip_one_byte(current)
            return (BlobResult(ok=True, reason="modified", blob=served,
                               served_hash=sha256(record_id.encode(), served.ciphertext).hex()),
                    "modified")

        return (BlobResult(ok=True, reason="honest", blob=current,
                           served_hash=sha256(record_id.encode(), current.ciphertext).hex()),
                f"honest v{current.version}")

    def served_snapshot(self, patient_id: str) -> list[tuple[str, int, bytes | None]]:
        """Every record as the cloud would serve it, for the PIR database (M5).

        One log line for the whole snapshot: the PIR server touches every row on
        every query, so a per-record entry here would be a lie about what it saw.
        """
        patient = self._patients.get(patient_id)
        rows: list[tuple[str, int, bytes | None]] = []
        if patient:
            for record_id in patient.record_ids():
                result, _ = self._serve(patient.records[record_id], None)
                rows.append((record_id, result.blob.version, result.blob.ciphertext)
                            if result.ok else (record_id, 0, None))
        self.access_log.append({"patient": patient_id, "record_id": "*",
                                "served": f"pir snapshot of {len(rows)} rows"})
        return rows

    # -- bulk views -------------------------------------------------------
    def list_records(self, patient_id: str) -> list[str]:
        patient = self._patients.get(patient_id)
        return patient.record_ids() if patient else []

    def get_all_content_hashes(self, patient_id: str) -> list[tuple[str, str, int]]:
        """`(record_id, content_hash, version)` for the latest version of each record.

        The Merkle root is always built from this function's output, so the tree
        and the on-chain commitment cannot drift apart.
        """
        patient = self._patients.get(patient_id)
        if not patient:
            return []
        return [(record_id, patient.latest(record_id).content_hash,
                 patient.latest(record_id).version)
                for record_id in patient.record_ids()]

    def decrypt(self, dek: bytes, blob: StoredBlob) -> bytes:
        """Open one blob. Raises `MedVaultCryptoError` on any mismatch."""
        return aes_gcm_decrypt(dek, blob.ciphertext)

    # -- internals --------------------------------------------------------
    @staticmethod
    def _flip_one_byte(blob: StoredBlob) -> StoredBlob:
        """Return the same record with exactly one byte changed.

        The last byte is the GCM tag, so the tamper is caught by both the
        content-hash check and the tag check — the two independent detections
        the design asks for.
        """
        tampered = bytearray(blob.ciphertext)
        tampered[-1] ^= 0x01
        return StoredBlob(blob.record_id, blob.content_hash, bytes(tampered),
                          blob.version, blob.patient_id)

    def total_bytes(self, patient_id: str) -> int:
        patient = self._patients.get(patient_id)
        if not patient:
            return 0
        return sum(len(b.ciphertext) for vs in patient.records.values() for b in vs)
