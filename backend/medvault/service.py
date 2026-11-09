"""One demo world: the patient, the doctors, and the four modules wired up (M1-M4).

This is the only place the modules meet each other. Each public method returns
`(result, trace)` where `trace` is the existing `ppseb.trace.Trace` event list,
so the UI renders every step without the backend growing a second protocol.

Key custody in the demo
-----------------------
The patient holds the DEKs, the index keys and the Merkle proofs. Each doctor
holds an ML-KEM keypair, an Ed25519 keypair, and whatever capability arrived in
their envelope — nothing else. A doctor therefore cannot decrypt a record by
reaching around the envelope, which is what makes the "wrong doctor" test a real
test rather than a flag check.

Revocation does not reach into the doctor's copy. A revoked doctor still holds
the epoch-N capability and the DEKs inside it; the gateway rejects because the
epoch moved. That is the documented limit (Requirement 4.16), modelled rather
than papered over.

Determinism: every secret here is derived from `MedVaultConfig.sub_seed`, is
labelled `TEST_KEY:` and is never printed. Deriving an index key from the
project seed is a demo choice (two rehearsals must agree) recorded in task
X-T2/X-T3, not a deployment choice.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import numpy as np

from ppseb.params import Params, default_params
from ppseb.scheme import initialization
from ppseb.trace import Trace

from .blob_store import BlobStore, StoredBlob
from .pir import PIRStore, PIRError
from .config import MedVaultConfig
from .consent import ConsentError, MemoryConsentLedger, justification_hash
from .crypto import (
    MedVaultCryptoError,
    SeededRandomSource,
    aes_gcm_decrypt,
    ed25519_keypair,
    sha256,
)
from .envelope import (
    Capability,
    Envelope,
    Scope,
    UnwrapResult,
    unwrap_capability,
    wrap_capability,
)
from .gateway import Gateway
from .zk import ZKAuthorisation, ConsentTree, field_id, signed_statement
from .kem import KEMWrapper, get_kem_wrapper
from .merkle import MerkleProofStep, MerkleTree
from .search import (
    ModeAIndex,
    RetrievalRequest,
    SearchIndex,
    SearchNode,
    SearchRequest,
    SearchResult,
    build_mode,
    normalize_keyword,
    retrieval_signing_message,
    sign_search_request,
)


def _merge_trace(trace: Trace, events: list[dict]) -> None:
    """Splice a child operation's events in, renumbering the steps.

    The UI renders events in step order (Requirement 9.5), so a merged trace holds
    exactly one 1..N sequence. `Trace.extend` does this for a `Trace` object; the
    gateway returns plain lists, and appending those directly would produce two
    events numbered 1.
    """
    for event in events:
        merged = dict(event)
        merged["step"] = len(trace.events) + 1
        trace.events.append(merged)


# --------------------------------------------------------------------------
# Small state objects
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ProofBundle:
    """The public data a doctor needs to check a record against the chain.

    A Merkle proof is public by nature: it proves inclusion without revealing
    anything else. The content hash inside it is also the value the doctor
    compares the served ciphertext against.
    """

    record_id: str
    content_hash: str
    version: int
    proof: tuple[MerkleProofStep, ...]
    root: bytes

    def as_dict(self) -> dict:
        return {
            "record_id": self.record_id,
            "content_hash": self.content_hash,
            "version": self.version,
            "root": self.root.hex(),
            "steps": [{"sibling": s.sibling.hex(), "direction": s.direction}
                      for s in self.proof],
        }


@dataclass
class DoctorAgent:
    """A doctor's own device: keys, plus whatever the patient handed them."""

    doctor_id: str
    signing_key: object
    kem_public: bytes
    kem_secret: bytes
    capability: Capability | None = None
    envelope: Envelope | None = None
    nonce_counter: int = 0
    last_request: SearchRequest | None = None
    received_epochs: list[int] = field(default_factory=list)
    proof_factory: object = field(default=None, repr=False)

    def receive(self, envelope: Envelope, *, kem: KEMWrapper) -> UnwrapResult:
        """Try to open an envelope addressed to somebody (maybe me)."""
        result = unwrap_capability(self.kem_secret, envelope, kem=kem)
        if result.ok:
            self.capability = result.capability
            self.envelope = envelope
            self.received_epochs.append(envelope.epoch)
        return result

    def next_nonce(self) -> int:
        self.nonce_counter += 1
        return self.nonce_counter

    def build_request(self, index: SearchIndex, keyword: str, nonce: int,
                      timestamp: int) -> SearchRequest:
        """Assemble and sign a search request from the held capability."""
        if self.capability is None:
            raise ConsentError("no_capability",
                               f"{self.doctor_id} holds no capability to search with")
        cap = self.capability
        token = index.compute_token(cap.index_key or None, keyword)
        signature = sign_search_request(self.signing_key, token, nonce, cap.epoch, timestamp)
        request = SearchRequest(
            token=token, nonce=nonce, epoch=cap.epoch, timestamp=timestamp,
            signature=signature, doctor_id=self.doctor_id,
            scope_hash=cap.scope.scope_hash(), keyword=keyword,
        )
        if self.proof_factory is not None:
            request.zk_proof = self.proof_factory(nonce)
        self.last_request = request
        return request

    def build_retrieval(self, record_id: str, nonce: int, timestamp: int) -> RetrievalRequest:
        """Sign a request to fetch one record (domain-separated from search)."""
        if self.capability is None:
            raise ConsentError("no_capability",
                               f"{self.doctor_id} holds no capability to retrieve with")
        epoch = self.capability.epoch
        signature = self.signing_key.sign(
            retrieval_signing_message(record_id, nonce, epoch, timestamp))
        return RetrievalRequest(record_id=record_id, nonce=nonce, epoch=epoch,
                                timestamp=timestamp, signature=signature,
                                doctor_id=self.doctor_id)

    def public_view(self) -> dict:
        return {
            "doctor_id": self.doctor_id,
            "has_capability": self.capability is not None,
            "capability_epoch": None if self.capability is None else self.capability.epoch,
            "envelope_epoch": None if self.envelope is None else self.envelope.epoch,
            "received_epochs": list(self.received_epochs),
            "nonce_counter": self.nonce_counter,
        }


# --------------------------------------------------------------------------
# The world
# --------------------------------------------------------------------------

class DemoWorld:
    """One patient, some doctors, one index mode, one ledger, one blob store."""

    def __init__(self, config: MedVaultConfig | None = None, *, mode: str | None = None,
                 params: Params | None = None, patient_id: str = "patient_alice",
                 kem: KEMWrapper | None = None) -> None:
        self.config = config or MedVaultConfig()
        self.mode = (mode or self.config.index_mode).upper()
        self.patient_id = patient_id
        self.params = params or default_params()
        self.kem = kem or get_kem_wrapper()

        self.ledger = MemoryConsentLedger()
        self.random = (SeededRandomSource(self._seed_bytes("demo-rng"))
                       if self.config.deterministic else None)
        self.store = BlobStore(random_source=self.random)
        self.node = SearchNode(
            require_patient_signature=(self.mode == "B"),
            shape_check_params=(self.params if self.mode == "A"
                                and self.config.ppseb_shape_check else None),
        )
        self.index = self._build_index()
        self.gateway = Gateway(
            ledger=self.ledger, search_node=self.node, index=self.index,
            mode=self.mode, key_resolver=self._resolve_doctor_key,
            patient_id=self.patient_id,
        )

        self.patient_signing = ed25519_keypair(
            seed=self._seed_bytes("patient-signing"), label="TEST_KEY:patient-signing")
        # Provisioned by the patient, never chosen by the index-write caller.
        self.node.trust_patient(self.patient_id, self.patient_signing.public_key())
        self.pir = PIRStore(slot_size=self.config.slot_size,
                            seed=self.config.sub_seed("pir-public-matrix"))
        self._index_keys: dict[tuple[str, int], bytes] = {}
        self._zk_secrets: dict[tuple[str, int], bytes] = {}
        self.zk = ZKAuthorisation(self.config.zk_mode)
        if self.config.ledger_mode == "hardhat":
            from .chain import HardhatConsentLedger
            self.ledger = HardhatConsentLedger(require_proof=self.zk.mode == "groth16")
            self.gateway.ledger = self.ledger
        self.consent_tree = None
        self.gateway.zk_verifier = self.zk if self.mode == "B" else None
        self.gateway.patient_key = self.patient_signing.public_key()
        self.doctors: dict[str, DoctorAgent] = {}
        self._deks: dict[str, bytes] = {}
        self._keywords: dict[str, list[str]] = {}
        self._proofs: dict[str, ProofBundle] = {}
        self.root: bytes = b"\x00" * 32
        self.version: int = 0

    # -- construction helpers --------------------------------------------
    def _seed_bytes(self, label: str) -> bytes:
        return (self.config.sub_seed(label).to_bytes(32, "big")
                if self.config.deterministic else os.urandom(32))

    def _seal_nonce(self) -> bytes | None:
        """A reproducible envelope nonce when determinism is on, else None."""
        return self.random.random_bytes(12) if self.random is not None else None

    def _build_index(self):
        trace = None
        if self.mode == "A":
            # The baseline index owns the PPSEB keys: computing a mode-A token
            # means building a trapdoor, which is what Finding 1 is about.
            rng = np.random.default_rng(self.config.sub_seed("ppseb-initialization"))
            state = initialization(self.params, rng)
            return ModeAIndex(self.params, pk=state["pk_r0"], sk=state["sk_r0"],
                              mu=state["mu"], epoch=0,
                              seed=self.config.sub_seed("ppseb-mode-a"))
        return build_mode(self.mode, trace)

    def _resolve_doctor_key(self, doctor_id: str):
        agent = self.doctors.get(doctor_id)
        return agent.signing_key.public_key() if agent else None

    # -- keys -------------------------------------------------------------
    def _index_key(self, doctor_id: str, epoch: int) -> bytes:
        """Per-doctor per-epoch HMAC key (decision D1).

        Mode A has no keyed index, so this returns empty bytes there — the
        absence *is* the baseline.
        """
        if self.mode == "A":
            return b""
        key = (doctor_id, epoch)
        if key not in self._index_keys:
            self._index_keys[key] = self._seed_bytes(f"index:{doctor_id}:{epoch}")
        return self._index_keys[key]

    def _zk_secret(self, doctor_id: str, epoch: int) -> bytes:
        key = (doctor_id, epoch)
        if key not in self._zk_secrets:
            self._zk_secrets[key] = self._seed_bytes(f"zk:{doctor_id}:{epoch}")
        return self._zk_secrets[key]

    def add_doctor(self, doctor_id: str, *, register: bool = True) -> DoctorAgent:
        """Create a doctor's keys and (by default) register them on the ledger."""
        signing = ed25519_keypair(seed=self._seed_bytes(f"doctor-signing:{doctor_id}"),
                                  label=f"TEST_KEY:doctor-signing:{doctor_id}")
        kem_pk, kem_sk = self.kem.keygen(seed=self._seed_bytes(f"doctor-kem:{doctor_id}"))
        agent = DoctorAgent(doctor_id, signing, kem_pk, kem_sk)
        self.doctors[doctor_id] = agent
        if self.mode == "B":
            agent.proof_factory = lambda nonce: self.proof_for(doctor_id, nonce)
        if register:
            try:
                self.ledger.register_doctor(
                    doctor_id, sha256(signing.public_bytes), sha256(kem_pk))
            except ConsentError:
                pass  # already registered with the same keys: idempotent
        return agent

    # -- patient operations ----------------------------------------------
    def _rebuild_merkle(self, trace: Trace) -> None:
        rows = self.store.get_all_content_hashes(self.patient_id)
        leaves = [MerkleTree.leaf_hash(record_id, content_hash)
                  for record_id, content_hash, _ in rows]
        root, proofs = MerkleTree.build(leaves)
        snapshot = self.store.bump_snapshot(self.patient_id)
        self.ledger.put_record(self.patient_id, root, snapshot)
        self.root, self.version = root, snapshot
        self._proofs = {
            record_id: ProofBundle(record_id, content_hash, row_version,
                                  tuple(proofs[i]), root)
            for i, (record_id, content_hash, row_version) in enumerate(rows)
        }
        trace.matrix("Merkle root over the patient's records", np.frombuffer(root, dtype=np.uint8),
                     name="root", algo="Merkle",
                     detail=f"{len(leaves)} leaf/leaves, committed at snapshot {snapshot}")
        trace.result("Record root committed on-chain",
                     data={"root": root.hex()[:32], "version": snapshot,
                           "leaf_count": len(leaves)},
                     algo="Merkle")

    def upload_record(self, record_id: str, text: str, keywords: list[str], *,
                      tag: str | None = None) -> tuple[dict, list[dict]]:
        """Encrypt a record, commit its root, and index it for every live grant."""
        trace = Trace()
        plaintext = text.encode("utf-8")
        put = self.store.store(record_id, plaintext, patient_id=self.patient_id)
        self._deks[record_id] = put.dek
        self._keywords[record_id] = [normalize_keyword(k) for k in keywords]
        if tag:
            self.ledger.tag_record(record_id, tag)

        trace.compute(
            f"Encrypt {record_id} under a fresh AES-256-GCM key",
            detail="A new 256-bit DEK per record; the ciphertext is stored under "
                   "SHA256(record_id ‖ ciphertext) so a modified blob cannot pass "
                   "as the committed one.",
            data={"record_id": record_id, "plaintext_bytes": len(plaintext),
                  "ciphertext_bytes": put.size_bytes, "version": put.version,
                  "content_hash": put.content_hash[:32]},
            algo="BlobStore",
            highlight=True,
        )
        self._rebuild_merkle(trace)

        for doctor_id in self.ledger.active_doctors(self.patient_id):
            self._index_records_for(doctor_id, [record_id], trace)
        self._rewrap_active(trace)

        result = {
            "record_id": record_id,
            "content_hash": put.content_hash,
            "version": put.version,
            "ciphertext_bytes": put.size_bytes,
            "merkle_root": self.root.hex(),
            "keywords": list(self._keywords[record_id]),
            "tag": tag,
        }
        return result, trace.to_list()

    def grant_scope(self, doctor_id: str, scope: Scope, expiry_seconds: int = 86_400,
                    *, break_glass_justification: str | None = None
                    ) -> tuple[dict, list[dict]]:
        """Issue a grant and deliver the sealed capability to that doctor."""
        trace = Trace()
        if doctor_id not in self.doctors:
            self.add_doctor(doctor_id)

        if break_glass_justification is not None:
            grant = self.ledger.emergency_grant(
                self.patient_id, doctor_id, scope,
                justification_hash(break_glass_justification), expiry_seconds)
        else:
            grant = self.ledger.grant(self.patient_id, doctor_id, scope, expiry_seconds)

        trace.note(
            f"Grant {doctor_id} → {scope.describe()}",
            detail="Expiry is a duration from issuance; the epoch pins the grant to "
                   "the patient's current key period.",
            data=grant.public_view(), algo="ConsentRegistry", highlight=True,
        )

        capability = self._capability_for(doctor_id, grant)
        envelope = wrap_capability(self.doctors[doctor_id].kem_public, capability, kem=self.kem,
                                   seal_nonce=self._seal_nonce())
        unwrap = self.doctors[doctor_id].receive(envelope, kem=self.kem)
        trace.decision(
            f"Seal and deliver the capability to {doctor_id}",
            verdict="OPENED" if unwrap.ok else "FAILED",
            evidence={"kem_label": envelope.kem_label,
                      "envelope_bytes": envelope.size_bytes(),
                      "dek_count": len(capability.deks),
                      "epoch": capability.epoch,
                      "recipient_key_hash": envelope.recipient_key_hash.hex()[:16]},
            detail="ML-KEM-768 encapsulation + HKDF-SHA-256 + AES-256-GCM. Only the "
                   "holder of the doctor's secret key can open it.",
            algo="Envelope", highlight=True,
        )

        self._index_records_for(doctor_id, list(self._keywords), trace)
        self._refresh_consent_tree(trace)
        result = {
            "doctor_id": doctor_id,
            "scope": scope.describe(),
            "scope_hash": scope.scope_hash().hex(),
            "expiry_seconds": expiry_seconds,
            "epoch": grant.epoch,
            "envelope": envelope.public_summary(),
            "capability": capability.public_summary(),
            "opened_by_recipient": unwrap.ok,
        }
        return result, trace.to_list()

    def revoke_doctor(self, doctor_id: str) -> tuple[dict, list[dict]]:
        """Revoke, bump the epoch, re-wrap for the rest, and measure the cost."""
        trace = Trace()
        started = time.perf_counter()
        old_epoch = self.ledger.current_epoch(self.patient_id)
        new_epoch, timestamp = self.ledger.revoke(self.patient_id, doctor_id)

        trace.decision(
            f"Revoke {doctor_id}",
            verdict="REVOKED",
            evidence={"old_epoch": old_epoch, "new_epoch": new_epoch,
                      "timestamp": timestamp},
            detail="The epoch increments, so every capability, token and request "
                   "issued under the old epoch is now stale — without having to "
                   "enumerate any of them.",
            algo="ConsentRegistry", highlight=True,
        )

        dropped = self.node.drop_epochs_below(doctor_id, new_epoch)
        trace.note(f"Erased {doctor_id}'s index epochs below {new_epoch}",
                   data={"dropped_entries": dropped}, algo="SearchNode")

        re_key = 0
        re_wrap = 0
        re_index = 0
        for other in self.ledger.active_doctors(self.patient_id):
            # A surviving grant has to be re-stamped at the new epoch, otherwise
            # the revocation would lock out everybody except the revoked doctor.
            grant = self.ledger.reissue_grant(self.patient_id, other, new_epoch)
            re_key += 1                                   # fresh index key this epoch
            capability = self._capability_for(other, grant)
            envelope = wrap_capability(self.doctors[other].kem_public, capability, kem=self.kem,
                                       seal_nonce=self._seal_nonce())
            self.doctors[other].receive(envelope, kem=self.kem)
            re_wrap += 1
            scope = grant.scope
            in_scope = [rid for rid in self._keywords
                        if scope.contains(rid, self._tags())]
            re_index += self._index_records_for(other, in_scope, trace)

        self._refresh_consent_tree(trace)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        cost = {
            "time_ms": round(elapsed_ms, 3),
            "transactions": 1,
            "re_key_ops": re_key,
            "re_wrap_ops": re_wrap,
            "re_index_ops": re_index,
            "dropped_entries": dropped,
            "epoch": new_epoch,
        }
        trace.result("Revocation cost measured",
                     data=cost, algo="ConsentRegistry", highlight=True)
        result = {
            "doctor_id": doctor_id,
            "new_epoch": new_epoch,
            "old_epoch": old_epoch,
            "remaining_doctors": self.ledger.active_doctors(self.patient_id),
            "cost": cost,
        }
        return result, trace.to_list()

    def _refresh_consent_tree(self, trace: Trace | None = None) -> None:
        doctors = self.ledger.active_doctors(self.patient_id)
        if self.zk.mode == "groth16":
            grants = []
            for doctor in doctors:
                cap = self.doctors[doctor].capability
                grants.append((doctor, field_id(cap.zk_secret),
                               field_id(cap.scope.scope_hash()), cap.epoch))
            self.consent_tree = ConsentTree(grants)
            root = self.consent_tree.root.to_bytes(32, "big")
        else:
            # Signed fallback makes no Poseidon or zero-knowledge claim.
            root = sha256(*(signed_statement(d, self.doctors[d].capability.scope.scope_hash(),
                                              self.doctors[d].capability.epoch) for d in doctors))
        self.ledger.set_consent_root(self.patient_id, root)
        if trace is not None:
            trace.note("Consent root updated", data={"root": root.hex(),
                       "live_leaves": len(doctors), "proof_mode": self.zk.label}, algo="ZK")

    def proof_for(self, doctor_id: str, nonce: int) -> dict:
        cap = self.doctors[doctor_id].capability
        if cap is None:
            raise ConsentError("no_capability")
        if self.zk.mode == "signed":
            return {"kind": "signed", "signature": self.patient_signing.sign(
                signed_statement(doctor_id, cap.scope.scope_hash(), cap.epoch)).hex()}
        if self.consent_tree is None or doctor_id not in self.consent_tree.positions:
            # Revoked doctors can still submit their saved proof; a new proof is unavailable.
            return {"kind": "groth16", "proof": {}, "public_inputs": []}
        elements, bits = self.consent_tree.path(doctor_id)
        return self.zk.generate_proof(field_id(cap.zk_secret), field_id(cap.scope.scope_hash()),
                                     nonce, elements, bits, self.consent_tree.root, cap.epoch)

    def set_consent_root(self, root: bytes) -> None:
        """M6 hook: publish the consent Merkle root for ZK authorisation."""
        self.ledger.set_consent_root(self.patient_id, root)

    def _tags(self) -> dict[str, str]:
        return self.ledger.tags()

    def _capability_for(self, doctor_id: str, grant=None) -> Capability:
        epoch = self.ledger.current_epoch(self.patient_id)
        grant = grant or self.ledger.get_grant(self.patient_id, doctor_id)
        scope = grant.scope if grant else Scope.record_set([])
        tags = self._tags()
        deks = {rid: dek for rid, dek in self._deks.items()
                if scope.contains(rid, tags)}
        return Capability(
            doctor_id=doctor_id,
            patient_id=self.patient_id,
            epoch=epoch,
            scope=scope,
            index_key=self._index_key(doctor_id, epoch),
            deks=deks,
            zk_secret=self._zk_secret(doctor_id, epoch),
        )

    def _index_records_for(self, doctor_id: str, record_ids: list[str],
                           trace: Trace | None = None) -> int:
        """(Re)build one doctor's index entries for the given records."""
        agent = self.doctors.get(doctor_id)
        if agent is None or agent.capability is None:
            return 0
        capability = agent.capability
        epoch = capability.epoch
        if epoch != self.ledger.current_epoch(self.patient_id):
            return 0
        pairs: list[tuple[str, str]] = []
        # Replace each record's entries so rewritten keywords do not remain live.
        self.node.remove_records(doctor_id, epoch, record_ids)
        for record_id in record_ids:
            if self.mode == "B" and not capability.scope.contains(record_id, self._tags()):
                continue
            for keyword in self._keywords.get(record_id, []):
                pairs.append((record_id, keyword))
        if not pairs:
            return 0
        entries = self.index.build(
            pairs, index_key=capability.index_key or None, epoch=epoch,
            doctor_id=doctor_id, signing_key=self.patient_signing,
        )
        accepted, rejected = self.node.add_entries(
            entries, self.patient_signing.public_key(), self.patient_id)
        if trace is not None:
            trace.compute(
                f"Index {len(accepted)} entr(ies) for {doctor_id} at epoch {epoch}",
                detail="Entries are patient-signed; an unsigned or foreign entry is "
                       "refused by the search node.",
                data={"accepted": len(accepted), "rejected": rejected,
                      "mode": self.mode},
                algo="SearchNode",
            )
        return len(accepted)

    def _rewrap_active(self, trace: Trace | None = None) -> int:
        count = 0
        for doctor_id in self.ledger.active_doctors(self.patient_id):
            capability = self._capability_for(doctor_id)
            envelope = wrap_capability(self.doctors[doctor_id].kem_public, capability,
                                       kem=self.kem, seal_nonce=self._seal_nonce())
            self.doctors[doctor_id].receive(envelope, kem=self.kem)
            count += 1
        if trace is not None and count:
            trace.note(f"Re-wrapped {count} envelope(s) to cover the new record",
                       data={"count": count}, algo="Envelope")
        return count

    # -- doctor operations -----------------------------------------------
    def search(self, doctor_id: str, keyword: str) -> tuple[dict, list[dict]]:
        """Build, sign and submit a search request through the gateway."""
        trace = Trace()
        agent = self.doctors.get(doctor_id)
        if agent is None or agent.capability is None:
            trace.decision(f"{doctor_id} holds no capability",
                           verdict="REJECTED",
                           evidence={"reason": "no_capability", "doctor": doctor_id},
                           algo="Doctor")
            return {"ok": False, "reason": "no_capability", "record_ids": []}, trace.to_list()

        nonce = agent.next_nonce()
        timestamp = self.ledger.now()
        request = agent.build_request(self.index, keyword, nonce, timestamp)
        trace.note(
            f"{doctor_id} signs a search request",
            detail="Ed25519 over (token, nonce, epoch, timestamp); the token itself "
                   "is never written to the chain.",
            data={"nonce": nonce, "epoch": request.epoch, "mode": self.mode,
                  "token": request.token.hex()[:16]},
            algo="SearchRequest",
        )
        result: SearchResult = self.gateway.handle_search(request)
        _merge_trace(trace, result.trace)
        return {
            "ok": result.ok,
            "reason": result.reason,
            "record_ids": result.record_ids,
            "keyword": keyword,
            "nonce": nonce,
            "epoch": request.epoch,
            "mode": self.mode,
        }, trace.to_list()

    def submit_request(self, request: SearchRequest) -> tuple[dict, list[dict]]:
        """Submit an already-built request — how the replay attack re-sends one."""
        trace = Trace()
        result = self.gateway.handle_search(request)
        _merge_trace(trace, result.trace)
        return {
            "ok": result.ok,
            "reason": result.reason,
            "record_ids": result.record_ids,
            "nonce": request.nonce,
            "epoch": request.epoch,
            "mode": self.mode,
        }, trace.to_list()

    def retrieve(self, doctor_id: str, record_id: str) -> tuple[dict, list[dict]]:
        """Fetch, verify, then decrypt — in that order, with no plaintext on failure."""
        trace = Trace()
        agent = self.doctors.get(doctor_id)
        if agent is None or agent.capability is None:
            return self._fail(trace, "no_capability", doctor_id, record_id)
        request = agent.build_retrieval(record_id, agent.next_nonce(), self.ledger.now())
        trace.note(
            f"{doctor_id} signs a retrieval request",
            detail="Ed25519 over (record id, nonce, epoch, timestamp), domain-separated "
                   "from search; the nonce comes from the same counter as searches.",
            data={"nonce": request.nonce, "epoch": request.epoch, "mode": self.mode},
            algo="RetrievalRequest",
        )
        return self._retrieve(request, trace, decrypt=True)

    def submit_retrieval(self, request: RetrievalRequest) -> tuple[dict, list[dict]]:
        """Submit an already-built retrieval — how the replay attack re-sends one.

        The replaying party holds no DEK, so this path never decrypts: success
        means the ciphertext was handed over, which is exactly what deck finding
        7 says the attacker gets.
        """
        return self._retrieve(request, Trace(), decrypt=False)

    def _retrieve(self, request: RetrievalRequest, trace: Trace, *,
                  decrypt: bool) -> tuple[dict, list[dict]]:
        doctor_id, record_id = request.doctor_id, request.record_id
        agent = self.doctors.get(doctor_id)
        if agent is None or agent.capability is None:
            return self._fail(trace, "no_capability", doctor_id, record_id)

        capability = agent.capability
        auth = self.gateway.authorize_retrieval(request)
        trace.decision(
            f"Authorise retrieval of {record_id} for {doctor_id}",
            verdict="AUTHORISED" if auth.ok else "REJECTED",
            evidence={"reason": auth.reason, "epoch": request.epoch,
                      "nonce": request.nonce},
            detail=auth.detail, algo="Gateway", highlight=True,
        )
        if not auth.ok:
            return self._fail(trace, auth.reason, doctor_id, record_id, trace_only=True)

        bundle = self._proofs.get(record_id)
        if bundle is None:
            return self._fail(trace, "not_found", doctor_id, record_id, trace_only=True)

        onchain_root, onchain_version = self.ledger.record_root(self.patient_id)
        try:
            # Load a complete served snapshot; never send the selected record ID
            # to BlobStore.get or PIRServer.answer.
            self.pir.load(self.store.served_snapshot(self.patient_id))
            row = self.pir.directory.index(record_id)  # client-side directory lookup
            served_version, ciphertext, pir_sizes = self.pir.fetch(row)
        except (PIRError, ValueError) as exc:
            return self._fail(trace, "pir_failed", doctor_id, record_id,
                              extra={"detail": str(exc)})
        trace.compute("Private retrieval via LWE PIR", data=pir_sizes, algo="PIR",
                      detail="Storage sees encrypted query and sizes, not row index. "
                             "Search node still sees matching IDs; collusion defeats privacy.")
        if not ciphertext:
            return self._fail(trace, "withheld", doctor_id, record_id)
        blob = StoredBlob(record_id, bundle.content_hash, ciphertext,
                          served_version, self.patient_id)
        if blob.version != bundle.version:
            return self._fail(trace, "stale_version", doctor_id, record_id, trace_only=True,
                              extra={"served_version": blob.version,
                                     "committed_version": bundle.version,
                                     "snapshot": onchain_version})

        served_hash = sha256(record_id.encode("utf-8"), blob.ciphertext).hex()
        if served_hash != bundle.content_hash:
            return self._fail(trace, "content_hash_mismatch", doctor_id, record_id,
                              trace_only=True,
                              extra={"served_hash": served_hash[:32],
                                     "committed_hash": bundle.content_hash[:32]})

        leaf = MerkleTree.leaf_hash(record_id, bundle.content_hash)
        if not MerkleTree.verify(leaf, list(bundle.proof), onchain_root):
            return self._fail(trace, "merkle_proof_failed", doctor_id, record_id,
                              trace_only=True)
        if bundle.root != onchain_root:
            return self._fail(trace, "root_mismatch", doctor_id, record_id, trace_only=True)

        trace.decision(
            "Integrity verified before decryption",
            verdict="VERIFIED",
            evidence={"content_hash": bundle.content_hash[:32],
                      "version": blob.version,
                      "proof_depth": len(bundle.proof)},
            detail="Stale version, altered bytes, a bad proof and a root mismatch all "
                   "stop here — before any DEK is used.",
            algo="Merkle", highlight=True,
        )

        if not decrypt:
            trace.result(f"Ciphertext of {record_id} handed over (not decrypted)",
                         data={"bytes": len(blob.ciphertext), "record_id": record_id},
                         algo="BlobStore")
            return {"ok": True, "reason": "fetched", "record_id": record_id,
                    "plaintext": None, "ciphertext_bytes": len(blob.ciphertext),
                    "version": blob.version, "pir": pir_sizes}, trace.to_list()

        dek = capability.deks.get(record_id)
        if dek is None:
            return self._fail(trace, "not_in_scope", doctor_id, record_id, trace_only=True)
        try:
            plaintext = aes_gcm_decrypt(dek, blob.ciphertext)
        except MedVaultCryptoError:
            return self._fail(trace, "decrypt_failed", doctor_id, record_id, trace_only=True)

        trace.result(
            f"Decrypted {record_id}",
            data={"bytes": len(plaintext), "record_id": record_id},
            algo="BlobStore",
        )
        return {
            "ok": True,
            "reason": "retrieved",
            "record_id": record_id,
            "plaintext": plaintext.decode("utf-8", errors="replace"),
            "version": blob.version,
            "content_hash": bundle.content_hash,
            "merkle_root": onchain_root.hex(),
            "pir": pir_sizes,
        }, trace.to_list()

    def _fail(self, trace: Trace, reason: str, doctor_id: str, record_id: str,
              *, trace_only: bool = False, extra: dict | None = None) -> tuple[dict, list[dict]]:
        """Fail closed: a reason and no plaintext. There is no partial success."""
        trace.decision(
            f"Retrieval refused: {reason}",
            verdict="FAIL_CLOSED",
            evidence={"reason": reason, "doctor": doctor_id, "record_id": record_id,
                      **(extra or {})},
            detail="No plaintext is produced when any check fails.",
            algo="BlobStore", highlight=True,
        )
        result = {"ok": False, "reason": reason, "record_id": record_id,
                  "plaintext": None, **(extra or {})}
        return result, trace.to_list()

    # -- inspection -------------------------------------------------------
    def open_envelope_as(self, doctor_id: str, envelope: Envelope,
                         opener_id: str) -> dict:
        """Show that an envelope opens only for its intended recipient."""
        opener = self.doctors.get(opener_id)
        if opener is None:
            raise KeyError(f"unknown doctor {opener_id!r}")
        result = unwrap_capability(opener.kem_secret, envelope, kem=self.kem)
        return {
            "envelope_for": doctor_id,
            "opener": opener_id,
            "ok": result.ok,
            "reason": result.reason,
            "capability": result.capability.public_summary() if result.capability else None,
        }

    def state(self) -> dict:
        """The whole world as the UI may see it. Contains no secret bytes."""
        return {
            "patient_id": self.patient_id,
            "mode": self.mode,
            "kem_label": self.kem.label(),
            "ledger_backend": self.ledger.backend_label,
            "proof_mode": self.zk.label,
            "deterministic_test_keys": self.config.deterministic,
            "pir": {"slot_size": self.pir.slot_size, "lwe_dim": self.pir.lwe_dim},
            "consent_root": self.ledger.consent_root(self.patient_id).hex(),
            "gate_policy": self.gateway.gate_policy(),
            "records": [
                {"record_id": record_id, "content_hash": content_hash, "version": version}
                for record_id, content_hash, version in
                self.store.get_all_content_hashes(self.patient_id)
            ],
            "merkle_root": self.root.hex(),
            "version": self.version,
            "doctors": [agent.public_view() for agent in self.doctors.values()],
            "grants": [g.public_view() for g in self.ledger.grant_history()],
            "epoch": self.ledger.current_epoch(self.patient_id),
            "index": self.node.snapshot_for_audit(),
            "chain_log": self.ledger.chain_log(),
            "audit_log": self.ledger.audit_view(),
            "evil_mode": self.store.evil_mode,
            "proofs": {rid: {k: v for k, v in bundle.as_dict().items() if k != "steps"}
                       for rid, bundle in self._proofs.items()},
        }

    def set_evil_mode(self, mode: str) -> None:
        self.store.set_evil_mode(mode)

    def advance_time(self, seconds: int) -> int:
        return self.ledger.advance_clock(seconds)


# --------------------------------------------------------------------------
# Default wiring used by the API and by repro.sh
# --------------------------------------------------------------------------

DEMO_DOCTORS = ("doctor_a", "doctor_b", "doctor_c")


def build_world(config: MedVaultConfig | None = None, *, mode: str | None = None) -> DemoWorld:
    """A world with three doctors registered and ready to be granted."""
    world = DemoWorld(config, mode=mode)
    for doctor_id in DEMO_DOCTORS:
        world.add_doctor(doctor_id)
    return world
