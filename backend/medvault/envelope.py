"""Capability envelopes: ML-KEM encapsulation, HKDF, AES-256-GCM (M2).

Requirement 2. The patient's grant to a doctor is a bundle — the doctor's index
key, the DEKs for the records in scope, and the doctor's ZK secret. That bundle
never travels in the clear: it is sealed under a key that only the holder of the
doctor's ML-KEM secret key can re-derive.

The one thing worth understanding here
-------------------------------------
ML-KEM `decaps` with the wrong secret key does **not** fail. It returns a
different, pseudorandom shared secret (implicit rejection). So the thing that
actually rejects a wrong doctor or a tampered envelope is the AES-GCM tag on the
sealed payload. That is deliberately a two-layer construction, and it is why
Requirement 2.4/2.5 are satisfied by a hard failure and never by a partial
Capability.

Epoch and scope live *inside* the authenticated payload (Requirement 2.2) and
are also mirrored outside it so a caller can decide whether to bother opening
the envelope. The mirrored copy is compared to the authenticated one after
unwrapping; a mismatch is treated as tampering.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from .crypto import (
    MedVaultCryptoError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    hkdf_sha256,
    sha256,
)
from .kem import KEMWrapper, get_kem_wrapper

ENVELOPE_INFO_PREFIX = b"medvault-envelope-v1"


# --------------------------------------------------------------------------
# Data
# --------------------------------------------------------------------------

def _b64(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"))


@dataclass(frozen=True)
class Scope:
    """Which records a doctor may reach: an explicit set, or a tag."""

    kind: str                                   # "record_set" | "record_tag"
    record_ids: tuple[str, ...] = ()
    tag: str = ""

    def __post_init__(self) -> None:
        if self.kind not in ("record_set", "record_tag"):
            raise ValueError(f"scope kind must be 'record_set' or 'record_tag', got {self.kind!r}")
        if self.kind == "record_set" and self.tag:
            raise ValueError("a record_set scope must not also carry a tag")

    @classmethod
    def record_set(cls, record_ids: list[str] | tuple[str, ...]) -> "Scope":
        return cls("record_set", tuple(sorted(record_ids)))

    @classmethod
    def record_tag(cls, tag: str) -> "Scope":
        return cls("record_tag", (), tag)

    def contains(self, record_id: str, tags: dict[str, str] | None = None) -> bool:
        """Membership test. Tags are resolved by the caller, not stored here."""
        if self.kind == "record_set":
            return record_id in self.record_ids
        return bool(tags) and tags.get(record_id, "") == self.tag

    def to_dict(self) -> dict:
        # Sorted tuple + fixed key order: scope_hash must be stable across runs.
        return {"kind": self.kind, "record_ids": list(self.record_ids), "tag": self.tag}

    @classmethod
    def from_dict(cls, payload: dict) -> "Scope":
        return cls(payload["kind"], tuple(payload.get("record_ids", ())), payload.get("tag", ""))

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    def scope_hash(self) -> bytes:
        return sha256(self.canonical_bytes())

    def describe(self) -> str:
        if self.kind == "record_set":
            return f"record_set[{', '.join(self.record_ids) or 'empty'}]"
        return f"record_tag[{self.tag}]"


@dataclass
class Capability:
    """What a doctor actually receives inside an envelope."""

    doctor_id: str
    patient_id: str
    epoch: int
    scope: Scope
    index_key: bytes                              # per-doctor per-epoch HMAC key
    deks: dict[str, bytes] = field(default_factory=dict)
    zk_secret: bytes = b""

    def to_dict(self) -> dict:
        return {
            "doctor_id": self.doctor_id,
            "patient_id": self.patient_id,
            "epoch": self.epoch,
            "scope": self.scope.to_dict(),
            "index_key": _b64(self.index_key),
            "deks": {k: _b64(v) for k, v in sorted(self.deks.items())},
            "zk_secret": _b64(self.zk_secret),
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":")).encode()

    @classmethod
    def from_dict(cls, payload: dict) -> "Capability":
        return cls(
            doctor_id=payload["doctor_id"],
            patient_id=payload["patient_id"],
            epoch=int(payload["epoch"]),
            scope=Scope.from_dict(payload["scope"]),
            index_key=_unb64(payload["index_key"]),
            deks={k: _unb64(v) for k, v in payload.get("deks", {}).items()},
            zk_secret=_unb64(payload.get("zk_secret", "")),
        )

    def public_summary(self) -> dict:
        """Everything safe to show: counts and identifiers, never key bytes."""
        return {
            "doctor_id": self.doctor_id,
            "patient_id": self.patient_id,
            "epoch": self.epoch,
            "scope": self.scope.describe(),
            "dek_count": len(self.deks),
            "zk_secret_present": bool(self.zk_secret),
        }


@dataclass(frozen=True)
class Envelope:
    """The sealed, transportable container for a Capability."""

    kem_ciphertext: bytes
    sealed_payload: bytes
    epoch: int
    scope_hash: bytes
    kem_label: str = ""
    #: Hash of the doctor's ML-KEM public key this was wrapped for. Public
    #: metadata; lets a wrong-doctor attempt be reported without opening.
    recipient_key_hash: bytes = b""

    def size_bytes(self) -> int:
        return len(self.kem_ciphertext) + len(self.sealed_payload)

    def public_summary(self) -> dict:
        return {
            "epoch": self.epoch,
            "scope_hash": self.scope_hash.hex()[:16],
            "kem_label": self.kem_label,
            "recipient_key_hash": self.recipient_key_hash.hex()[:16],
            "kem_ciphertext_bytes": len(self.kem_ciphertext),
            "sealed_payload_bytes": len(self.sealed_payload),
            "total_bytes": self.size_bytes(),
        }

    def to_dict(self) -> dict:
        return {
            "kem_ciphertext": _b64(self.kem_ciphertext),
            "sealed_payload": _b64(self.sealed_payload),
            "epoch": self.epoch,
            "scope_hash": self.scope_hash.hex(),
            "kem_label": self.kem_label,
            "recipient_key_hash": self.recipient_key_hash.hex(),
        }

    @classmethod
    def from_dict(cls, payload: dict) -> "Envelope":
        return cls(
            kem_ciphertext=_unb64(payload["kem_ciphertext"]),
            sealed_payload=_unb64(payload["sealed_payload"]),
            epoch=int(payload["epoch"]),
            scope_hash=bytes.fromhex(payload["scope_hash"]),
            kem_label=payload.get("kem_label", ""),
            recipient_key_hash=bytes.fromhex(payload.get("recipient_key_hash", "")),
        )


@dataclass
class UnwrapResult:
    """Fail-closed unwrap outcome: a Capability or a reason, never both."""

    ok: bool
    reason: str                    # opened | wrong_key_or_tampered | metadata_mismatch
    capability: Capability | None = None


# --------------------------------------------------------------------------
# Wrap / unwrap
# --------------------------------------------------------------------------

def wrap_capability(doctor_kem_public_key: bytes, capability: Capability, *,
                    kem: KEMWrapper | None = None,
                    encapsulation_seed: bytes | None = None,
                    seal_nonce: bytes | None = None) -> Envelope:
    """Seal a Capability to a doctor's ML-KEM public key (Requirement 2.1).

    `seal_nonce` exists only so a demo run is byte-reproducible (Requirement
    10.10); the default lets AES-GCM draw a fresh random nonce.
    """
    kem = kem or get_kem_wrapper()
    kem_ciphertext, shared_secret = kem.encaps(doctor_kem_public_key,
                                               seed=encapsulation_seed)
    aes_key = hkdf_sha256(
        shared_secret,
        info=ENVELOPE_INFO_PREFIX + capability.epoch.to_bytes(4, "big"),
    )
    sealed = aes_gcm_encrypt(aes_key, capability.canonical_bytes(), nonce=seal_nonce)
    return Envelope(
        kem_ciphertext=kem_ciphertext,
        sealed_payload=sealed,
        epoch=capability.epoch,
        scope_hash=capability.scope.scope_hash(),
        kem_label=kem.label(),
        recipient_key_hash=sha256(doctor_kem_public_key),
    )


def unwrap_capability(doctor_kem_secret_key: bytes, envelope: Envelope, *,
                      kem: KEMWrapper | None = None) -> UnwrapResult:
    """Open an envelope, or fail closed with a named reason (Requirement 2.4/2.5)."""
    kem = kem or get_kem_wrapper()
    shared_secret = kem.decaps(doctor_kem_secret_key, envelope.kem_ciphertext)
    aes_key = hkdf_sha256(
        shared_secret,
        info=ENVELOPE_INFO_PREFIX + envelope.epoch.to_bytes(4, "big"),
    )
    try:
        payload = aes_gcm_decrypt(aes_key, envelope.sealed_payload)
    except MedVaultCryptoError:
        return UnwrapResult(ok=False, reason="wrong_key_or_tampered")

    try:
        capability = Capability.from_dict(json.loads(payload))
    except (ValueError, KeyError, TypeError):
        return UnwrapResult(ok=False, reason="wrong_key_or_tampered")

    # The mirrored metadata is only a hint until it agrees with the inside.
    if capability.epoch != envelope.epoch:
        return UnwrapResult(ok=False, reason="metadata_mismatch")
    if capability.scope.scope_hash() != envelope.scope_hash:
        return UnwrapResult(ok=False, reason="metadata_mismatch")
    return UnwrapResult(ok=True, reason="opened", capability=capability)


def tamper(envelope: Envelope, *, position: int | None = None) -> Envelope:
    """Flip one byte of an envelope, for the tamper test (Requirement 2.5)."""
    payload = bytearray(envelope.sealed_payload)
    index = len(payload) - 1 if position is None else position % len(payload)
    payload[index] ^= 0x01
    return Envelope(
        kem_ciphertext=envelope.kem_ciphertext,
        sealed_payload=bytes(payload),
        epoch=envelope.epoch,
        scope_hash=envelope.scope_hash,
        kem_label=envelope.kem_label,
        recipient_key_hash=envelope.recipient_key_hash,
    )
