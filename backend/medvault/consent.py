"""Consent registry: doctors, grants, epochs, roots, audit log (M4).

Requirements 4. One interface (`ConsentLedger`) with one implementation in this
build: `MemoryConsentLedger`, a deterministic in-process ledger that behaves
exactly like the contract sketch in design.md — same state, same events, same
rejections — without needing a chain process for the demo to start.

That choice is stated rather than hidden: `backend_label()` returns
`memory-ledger` and the UI shows it, the same way the KEM label is shown. The
Solidity backend is a P1 task (M4-T9) because a contract that is never compiled
on the demo laptop would be an untested claim.

The epoch is the load-bearing idea here. Revoking a doctor bumps the patient's
epoch; every capability, token and request carries the epoch it was issued under,
so one integer invalidates everything issued before the revocation without
having to enumerate it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable

from .crypto import sha256
from .envelope import Scope

# Requirement 4.2: expiry is a duration in seconds, bounded at both ends.
MIN_GRANT_SECONDS = 60
MAX_GRANT_SECONDS = 365 * 24 * 3600      # 31 536 000
MAX_BREAK_GLASS_SECONDS = 3600           # Requirement 4.12

EVENT_TYPES = ("doctor_registered", "grant", "revoke", "epoch_change",
               "record_committed", "consent_root", "search_commitment",
               "break_glass")


class ConsentError(Exception):
    """A request the registry refuses. Carries a machine-readable reason."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(detail or reason)
        self.reason = reason
        self.detail = detail


class LogicalClock:
    """A deterministic second-counter clock.

    Wall-clock time would make two identical demo runs disagree in the audit
    log, which breaks Requirement 10.10 for no benefit: nothing here needs real
    time, and expiry is specified as a *duration* from issuance. Tests advance it
    explicitly.
    """

    BASE = 1_700_000_000

    def __init__(self, start: int | None = None, step: int = 1) -> None:
        self._now = self.BASE if start is None else start
        self._step = step

    def __call__(self) -> int:
        self._now += self._step
        return self._now

    def peek(self) -> int:
        return self._now

    def advance(self, seconds: int) -> int:
        self._now += seconds
        return self._now


@dataclass
class DoctorRecord:
    doctor_id: str
    sig_key_hash: bytes
    kem_key_hash: bytes
    registered: bool = True

    def public_view(self) -> dict:
        return {"doctor_id": self.doctor_id,
                "sig_key_hash": self.sig_key_hash.hex()[:16],
                "kem_key_hash": self.kem_key_hash.hex()[:16],
                "registered": self.registered}


@dataclass
class Grant:
    patient_id: str
    doctor_id: str
    scope: Scope
    scope_hash: bytes
    expiry_seconds: int
    epoch: int
    issued_at: int
    active: bool = True
    revoked: bool = False
    is_break_glass: bool = False
    justification_hash: bytes = b""

    def expires_at(self) -> int:
        return self.issued_at + self.expiry_seconds

    def is_valid_at(self, now: int) -> bool:
        return self.active and not self.revoked and now <= self.expires_at()

    def public_view(self) -> dict:
        return {
            "patient_id": self.patient_id,
            "doctor_id": self.doctor_id,
            "scope": self.scope.describe(),
            "scope_hash": self.scope_hash.hex()[:16],
            "expiry_seconds": self.expiry_seconds,
            "epoch": self.epoch,
            "issued_at": self.issued_at,
            "active": self.active,
            "revoked": self.revoked,
            "break_glass": self.is_break_glass,
        }


@dataclass
class AuditEvent:
    event_id: int
    event_type: str
    patient_id: str
    doctor_id: str
    epoch: int
    timestamp: int
    data_hash: str
    note: str = ""

    def public_view(self) -> dict:
        return {
            "event_id": self.event_id,
            "type": self.event_type,
            "patient": self.patient_id,
            "doctor": self.doctor_id,
            "epoch": self.epoch,
            "timestamp": self.timestamp,
            "data_hash": self.data_hash[:16],
            "note": self.note,
        }


class ConsentLedger(ABC):
    """What the gateway and the patient operations are allowed to ask for."""

    @property
    @abstractmethod
    def backend_label(self) -> str:
        ...

    @abstractmethod
    def register_doctor(self, doctor_id: str, sig_key_hash: bytes, kem_key_hash: bytes) -> None:
        ...

    @abstractmethod
    def grant(self, patient_id: str, doctor_id: str, scope: Scope,
              expiry_seconds: int) -> Grant:
        ...

    @abstractmethod
    def revoke(self, patient_id: str, doctor_id: str) -> tuple[int, int]:
        """Returns `(new_epoch, timestamp)`."""

    @abstractmethod
    def emergency_grant(self, patient_id: str, doctor_id: str, scope: Scope,
                        justification_hash: bytes, expiry_seconds: int) -> Grant:
        ...

    @abstractmethod
    def put_record(self, patient_id: str, root: bytes, version: int) -> None:
        ...

    @abstractmethod
    def set_consent_root(self, patient_id: str, root: bytes) -> None:
        ...

    @abstractmethod
    def request_search(self, patient_id: str, doctor_id: str, commitment: bytes,
                       nonce: int, *, public_token: bytes | None = None) -> AuditEvent:
        ...

    @abstractmethod
    def current_epoch(self, patient_id: str) -> int:
        ...

    @abstractmethod
    def has_valid_grant(self, doctor_id: str, scope_hash: bytes, epoch: int) -> bool:
        ...

    @abstractmethod
    def is_authorized(self, doctor_id: str, record_id: str) -> bool:
        ...

    @abstractmethod
    def get_grant(self, patient_id: str, doctor_id: str) -> Grant | None:
        ...

    @abstractmethod
    def active_doctors(self, patient_id: str) -> list[str]:
        ...

    @abstractmethod
    def reissue_grant(self, patient_id: str, doctor_id: str, epoch: int) -> Grant:
        """Re-stamp a surviving grant at the new epoch after a revocation."""

    @abstractmethod
    def audit_log(self) -> list[AuditEvent]:
        ...


class MemoryConsentLedger(ConsentLedger):
    """The deterministic reference ledger. One patient in the demo, many in tests."""

    def __init__(self, clock: Callable[[], int] | None = None) -> None:
        self._clock = clock or LogicalClock()
        self._doctors: dict[str, DoctorRecord] = {}
        self._grants: dict[tuple[str, str], Grant] = {}
        #: Every grant ever issued, in order — the audit view needs history, not
        #: just the current state, and a revoked grant must still be readable.
        self._grant_history: list[Grant] = []
        self._epochs: dict[str, int] = {}
        self._record_roots: dict[str, tuple[bytes, int]] = {}
        self._consent_roots: dict[str, bytes] = {}
        self._nullifiers: set[str] = set()
        self._search_commitments: list[dict] = []
        self._audit: list[AuditEvent] = []
        self._notes: dict[str, str] = {}      # record_id -> tag, for tag scopes

    # -- identity ---------------------------------------------------------
    @property
    def backend_label(self) -> str:
        return "memory-ledger"

    def now(self) -> int:
        return self._clock.peek() if hasattr(self._clock, "peek") else self._clock()

    def advance_clock(self, seconds: int) -> int:
        if hasattr(self._clock, "advance"):
            return self._clock.advance(seconds)  # type: ignore[union-attr]
        return self.now()

    # -- audit ------------------------------------------------------------
    def _log(self, event_type: str, patient_id: str, doctor_id: str, epoch: int,
             data_hash: str = "", note: str = "") -> AuditEvent:
        if event_type not in EVENT_TYPES:
            raise ValueError(f"unknown audit event type {event_type!r}")
        event = AuditEvent(
            event_id=len(self._audit) + 1,
            event_type=event_type,
            patient_id=patient_id,
            doctor_id=doctor_id,
            epoch=epoch,
            timestamp=self._clock(),
            data_hash=data_hash,
            note=note,
        )
        self._audit.append(event)
        return event

    def audit_log(self) -> list[AuditEvent]:
        """Chronological by construction: events are appended, never sorted."""
        return list(self._audit)

    def audit_view(self) -> list[dict]:
        return [event.public_view() for event in self._audit]

    # -- doctors and grants ----------------------------------------------
    def register_doctor(self, doctor_id: str, sig_key_hash: bytes, kem_key_hash: bytes) -> None:
        existing = self._doctors.get(doctor_id)
        if existing and existing.registered:
            if existing.sig_key_hash != sig_key_hash or existing.kem_key_hash != kem_key_hash:
                # Re-registering the same address with different keys would let
                # a doctor swap their identity under an existing grant.
                raise ConsentError("doctor_already_registered",
                                   "re-registration with different key hashes")
            return
        self._doctors[doctor_id] = DoctorRecord(doctor_id, sig_key_hash, kem_key_hash)
        self._log("doctor_registered", "", doctor_id, 0,
                  data_hash=(sig_key_hash + kem_key_hash).hex())

    def doctor(self, doctor_id: str) -> DoctorRecord | None:
        return self._doctors.get(doctor_id)

    def grant(self, patient_id: str, doctor_id: str, scope: Scope,
              expiry_seconds: int) -> Grant:
        self._validate_grant_inputs(patient_id, doctor_id, expiry_seconds)
        epoch = self.current_epoch(patient_id)
        grant = Grant(
            patient_id=patient_id,
            doctor_id=doctor_id,
            scope=scope,
            scope_hash=scope.scope_hash(),
            expiry_seconds=expiry_seconds,
            epoch=epoch,
            issued_at=self._clock(),
        )
        self._grants[(patient_id, doctor_id)] = grant
        self._grant_history.append(grant)
        self._log("grant", patient_id, doctor_id, epoch,
                  data_hash=grant.scope_hash.hex(),
                  note=f"scope_hash={scope.scope_hash().hex()} expiry={expiry_seconds}s")
        return grant

    def emergency_grant(self, patient_id: str, doctor_id: str, scope: Scope,
                        justification_hash: bytes, expiry_seconds: int) -> Grant:
        """Break-glass access: a mandatory justification and a hard short expiry."""
        if not justification_hash:
            raise ConsentError("missing_justification",
                               "emergency grants require a justification hash")
        if not 1 <= expiry_seconds <= MAX_BREAK_GLASS_SECONDS:
            raise ConsentError(
                "expiry_out_of_range",
                f"break-glass expiry must be 1..{MAX_BREAK_GLASS_SECONDS} seconds",
            )
        self._validate_grant_inputs(patient_id, doctor_id, expiry_seconds,
                                    allow_short=True)
        epoch = self.current_epoch(patient_id)
        grant = Grant(
            patient_id=patient_id,
            doctor_id=doctor_id,
            scope=scope,
            scope_hash=scope.scope_hash(),
            expiry_seconds=expiry_seconds,
            epoch=epoch,
            issued_at=self._clock(),
            is_break_glass=True,
            justification_hash=justification_hash,
        )
        self._grants[(patient_id, doctor_id)] = grant
        self._grant_history.append(grant)
        self._log("break_glass", patient_id, doctor_id, epoch,
                  data_hash=justification_hash.hex(),
                  note=f"expiry={expiry_seconds}s justification committed")
        return grant

    def _validate_grant_inputs(self, patient_id: str, doctor_id: str,
                               expiry_seconds: int, *, allow_short: bool = False) -> None:
        if not patient_id:
            raise ConsentError("invalid_grant", "a grant needs a patient")
        if not doctor_id:
            raise ConsentError("invalid_grant", "a grant needs a doctor")
        lower = 1 if allow_short else MIN_GRANT_SECONDS
        if not lower <= expiry_seconds <= MAX_GRANT_SECONDS:
            raise ConsentError(
                "expiry_out_of_range",
                f"expiry must be {lower}..{MAX_GRANT_SECONDS} seconds from issuance",
            )

    def revoke(self, patient_id: str, doctor_id: str) -> tuple[int, int]:
        """Revoke, bump the epoch, and log both facts (Requirement 4.5).

        The grant is kept in history with `revoked=True`: an audit view that
        erased it would be unable to show that the revocation happened.
        """
        grant = self._grants.get((patient_id, doctor_id))
        if grant is None:
            raise ConsentError("no_such_grant", f"no grant from {patient_id} to {doctor_id}")
        if grant.revoked:
            raise ConsentError("already_revoked", "this grant is already revoked")
        grant.active = False
        grant.revoked = True
        old_epoch = self.current_epoch(patient_id)
        new_epoch = old_epoch + 1
        self._epochs[patient_id] = new_epoch
        timestamp = self._clock()
        self._log("revoke", patient_id, doctor_id, old_epoch,
                  note=f"grant revoked at epoch {old_epoch}")
        self._log("epoch_change", patient_id, doctor_id, new_epoch,
                  note=f"epoch {old_epoch} -> {new_epoch}")
        return new_epoch, timestamp

    def get_grant(self, patient_id: str, doctor_id: str) -> Grant | None:
        return self._grants.get((patient_id, doctor_id))

    def grant_history(self) -> list[Grant]:
        return list(self._grant_history)

    def active_doctors(self, patient_id: str) -> list[str]:
        now = self.now()
        return sorted(
            doctor for (patient, doctor), grant in self._grants.items()
            if patient == patient_id and grant.is_valid_at(now)
        )

    def reissue_grant(self, patient_id: str, doctor_id: str, epoch: int) -> Grant:
        """Re-stamp a surviving grant at `epoch`.

        Revocation bumps the patient's epoch, which invalidates every capability
        issued under the old one — including the surviving doctors'. The patient
        therefore re-issues their grants at the new epoch as part of the same
        operation (Requirement 4.7). Without this, one revocation would silently
        lock out everybody else, which would look like a working demo and be a
        broken system.
        """
        grant = self._grants.get((patient_id, doctor_id))
        if grant is None:
            raise ConsentError("no_such_grant", f"no grant from {patient_id} to {doctor_id}")
        if grant.revoked:
            raise ConsentError("grant_revoked", "cannot re-issue a revoked grant")
        grant.epoch = epoch
        self._log("grant", patient_id, doctor_id, epoch,
                  data_hash=grant.scope_hash.hex(),
                  note=f"re-issued at epoch {epoch} after revocation")
        return grant

    def current_epoch(self, patient_id: str) -> int:
        return self._epochs.get(patient_id, 0)

    def has_valid_grant(self, doctor_id: str, scope_hash: bytes, epoch: int) -> bool:
        """A grant is usable only if it is live, current-epoch and in scope."""
        now = self.now()
        for grant in self._grants.values():
            if grant.doctor_id != doctor_id:
                continue
            if grant.scope_hash != scope_hash:
                continue
            if grant.epoch != epoch:
                continue
            if grant.is_valid_at(now):
                return True
        return False

    def is_authorized(self, doctor_id: str, record_id: str) -> bool:
        """Record-level check used before a retrieval (Requirement 4.4)."""
        now = self.now()
        for grant in self._grants.values():
            if grant.doctor_id != doctor_id or not grant.is_valid_at(now):
                continue
            if grant.scope.contains(record_id, self._notes):
                return True
        return False

    def tag_record(self, record_id: str, tag: str) -> None:
        """Attach a tag so `record_tag` scopes can be resolved."""
        self._notes[record_id] = tag

    def tags(self) -> dict[str, str]:
        """The record→tag index, for scope resolution."""
        return dict(self._notes)

    # -- record and consent roots ----------------------------------------
    def put_record(self, patient_id: str, root: bytes, version: int) -> None:
        previous = self._record_roots.get(patient_id)
        if previous is not None and version <= previous[1]:
            raise ConsentError("version_not_increasing",
                               f"version {version} <= current {previous[1]}")
        self._record_roots[patient_id] = (root, version)
        self._log("record_committed", patient_id, "", self.current_epoch(patient_id),
                  data_hash=f"{root.hex()}:{version}",
                  note=f"root committed at version {version}")

    def record_root(self, patient_id: str) -> tuple[bytes, int]:
        root, version = self._record_roots.get(patient_id, (b"\x00" * 32, 0))
        return root, version

    def set_consent_root(self, patient_id: str, root: bytes) -> None:
        self._consent_roots[patient_id] = root
        self._log("consent_root", patient_id, "", self.current_epoch(patient_id),
                  data_hash=root.hex(), note="consent root updated")

    def consent_root(self, patient_id: str) -> bytes:
        return self._consent_roots.get(patient_id, b"\x00" * 32)

    # -- search commitments ----------------------------------------------
    def request_search(self, patient_id: str, doctor_id: str, commitment: bytes,
                       nonce: int, *, public_token: bytes | None = None) -> AuditEvent:
        """Record a search commitment — the hash only, never the token.

        `public_token` exists for exactly one caller: the mode A gateway, which
        models PPSEB putting the search itself on-chain. Passing it writes the
        token into the observable log, which is Finding 4 made concrete. The
        mode B gateway never passes it, and the regression test asserts the
        hardened log contains no token.
        """
        record = {"doctor_id": doctor_id, "commitment": commitment.hex(), "nonce": nonce,
                  "epoch": self.current_epoch(patient_id)}
        if public_token is not None:
            record["public_token"] = public_token.hex()
        self._search_commitments.append(record)
        return self._log("search_commitment", patient_id, doctor_id,
                         self.current_epoch(patient_id),
                         data_hash=commitment.hex(), note=f"nonce={nonce}")

    def search_commitments(self) -> list[dict]:
        return list(self._search_commitments)

    # -- nullifiers (M6 fills these in) ----------------------------------
    def is_nullifier_used(self, nullifier: bytes) -> bool:
        return nullifier.hex() in self._nullifiers

    def add_nullifier(self, nullifier: bytes) -> None:
        self._nullifiers.add(nullifier.hex())

    def nullifier_count(self) -> int:
        return len(self._nullifiers)

    # -- inspection -------------------------------------------------------
    def state_summary(self) -> dict:
        """Everything an auditor may read, with no key material in it."""
        return {
            "backend": self.backend_label,
            "doctors": [d.public_view() for d in self._doctors.values()],
            "grants": [g.public_view() for g in self._grant_history],
            "epochs": dict(self._epochs),
            "record_roots": {p: {"root": r.hex()[:16], "version": v}
                             for p, (r, v) in self._record_roots.items()},
            "consent_roots": {p: r.hex()[:16] for p, r in self._consent_roots.items()},
            "search_commitments": len(self._search_commitments),
            "nullifiers": self.nullifier_count(),
            "audit_events": len(self._audit),
        }

    def chain_log(self) -> list[dict]:
        """What a passive chain observer would see (Requirement 11.1, 15.4).

        Commitments, event types, epochs and timestamps. No tokens, no record
        ids, no keywords. The regression test for Finding 4 asserts on this.
        """
        log = self.audit_view()
        log.extend({"type": "search_commitment_record", **c}
                   for c in self._search_commitments)
        return log


def scope_hash_of(scope: Scope) -> bytes:
    """The on-chain handle for a scope definition."""
    return scope.scope_hash()


def justification_hash(text: str) -> bytes:
    """Hash of a free-text justification. The text itself never goes on-chain."""
    return sha256(text.encode("utf-8"))
