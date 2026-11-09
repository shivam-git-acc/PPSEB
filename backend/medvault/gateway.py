"""The gateway: every gate that must pass before a search happens (M3/M4).

Requirements 3.7-3.10 and 3.22. The gate order is fixed and each gate is
independently observable in the trace, because the demo's argument is "here is
the exact gate that rejected this request", not "it returned 403".

Mode policy, stated plainly
--------------------------
The gateway has no authentication gates in mode A. That is not an oversight; it
is Finding 3. PPSEB moves the search itself on-chain and has no requester
authentication, so a captured trapdoor is simply reusable. Mode A expresses
that, mode B closes it, and `gate_policy()` is what the UI prints so nobody has
to take this paragraph on faith.

Nonce handling detail that matters: the nonce is only committed when *every*
gate passes. A rejected request must not burn a nonce, or a rejected request
would be a denial of service against the doctor (Requirement 3.9, Property 11).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from ppseb.trace import Trace

from .consent import ConsentLedger
from .crypto import VerifyKey
from .search import (
    RetrievalRequest,
    SearchIndex,
    SearchNode,
    SearchRequest,
    SearchResult,
    compute_commitment,
    retrieval_signing_message,
    verify_search_signature,
)

#: Which gates run in each mode. Mode A is the baseline: no requester auth.
GATE_POLICY = {
    "A": (),
    "B": ("signature", "epoch", "nonce", "scope"),
    # Mode C repairs keyword guessing only. It keeps PPSEB's open, public search
    # path on purpose, so replay and planting are measured, not hidden.
    "C": (),
}

REJECTION_REASONS = (
    "bad_signature",
    "stale_epoch",
    "reused_nonce",
    "out_of_scope",
    "bad_proof",
    "accepted",
)


@dataclass
class RetrievalAuthorisation:
    ok: bool
    reason: str
    detail: str = ""


class Gateway:
    """Validates a search request, then hands the token to the search node."""

    def __init__(self, *, ledger: ConsentLedger, search_node: SearchNode,
                 index: SearchIndex, mode: str = "B",
                 key_resolver: Callable[[str], VerifyKey | None] | None = None,
                 patient_id: str = "patient", zk_verifier=None,
                 patient_key=None) -> None:
        if mode not in GATE_POLICY:
            raise ValueError(f"gateway mode must be one of {tuple(GATE_POLICY)}, got {mode!r}")
        self.ledger = ledger
        self.search_node = search_node
        self.index = index
        self.mode = mode
        self.patient_id = patient_id
        self._key_resolver = key_resolver
        self._last_nonce: dict[str, int] = {}
        self.zk_verifier = zk_verifier
        self.patient_key = patient_key

    # -- introspection ----------------------------------------------------
    def gate_policy(self) -> dict:
        return {
            "mode": self.mode,
            "gates": list(GATE_POLICY[self.mode]) +
                     (["proof"] if self.zk_verifier is not None and self.mode == "B" else []),
            "note": {
                "A": "mode A is the baseline: no requester authentication, so a "
                     "captured token is replayable by construction",
                "B": "mode B rejects a bad signature, a stale epoch, a reused or "
                     "out-of-order nonce, and an out-of-scope request",
                "C": "mode C fixes keyword guessing only: the trapdoor is public and "
                     "Verify is public, but requests are not authenticated",
            }[self.mode],
        }

    def last_nonce(self, doctor_id: str) -> int:
        return self._last_nonce.get(doctor_id, 0)

    # -- the gate sequence ------------------------------------------------
    def handle_search(self, req: SearchRequest) -> SearchResult:
        """Run every gate, then search. Any failure means no search at all."""
        trace = Trace()
        gates = GATE_POLICY[self.mode]
        trace.note(
            f"Gateway checks (mode {self.mode})",
            detail=f"gates: {', '.join(gates) if gates else 'none — this is the finding'}",
            data=self.gate_policy(),
            algo="Gateway",
        )

        current_epoch = self.ledger.current_epoch(self.patient_id)

        if "signature" in gates:
            verify_key = self._resolve_key(req.doctor_id)
            ok = verify_key is not None and verify_search_signature(
                verify_key, req.signature, req.token, req.nonce, req.epoch, req.timestamp
            )
            if not ok:
                return self._reject(trace, "bad_signature",
                                    f"request for {req.doctor_id} at epoch {req.epoch}")

        if "epoch" in gates and req.epoch != current_epoch:
            return self._reject(trace, "stale_epoch",
                                f"request epoch {req.epoch}, patient epoch {current_epoch}")

        if "nonce" in gates:
            last = self.last_nonce(req.doctor_id)
            if req.nonce <= last:
                return self._reject(trace, "reused_nonce",
                                    f"nonce {req.nonce} <= last accepted {last}")

        if "scope" in gates:
            if not self.ledger.has_valid_grant(req.doctor_id, req.scope_hash, req.epoch):
                return self._reject(trace, "out_of_scope",
                                    f"no live grant for scope {req.scope_hash.hex()[:16]} "
                                    f"at epoch {req.epoch}")

        nullifier = None
        if self.mode == "B" and self.zk_verifier is not None:
            valid, nullifier = self.zk_verifier.check_request(
                req, self.ledger, self.patient_id, self.patient_key)
            if not valid:
                return self._reject(trace, "bad_proof", "Invalid proof, old root or reused nullifier")
            trace.decision("Authorization proof verified", verdict="VALID",
                           evidence={"label": self.zk_verifier.label,
                                     "verification_ms": self.zk_verifier.last_verification_ms},
                           algo="ZK")
        elif req.zk_proof is not None and self.mode == "B":
            return self._reject(trace, "bad_proof", "No configured verifier")

        # Every gate passed: commit the nonce, then and only then search.
        commitment = compute_commitment(req.token, req.nonce, req.epoch)
        if hasattr(self.ledger, "commit_search"):
            # Contract atomically commits proof/nullifier/nonce/search event.
            self.ledger.commit_search(self.patient_id, req, commitment, nullifier)
        else:
            self.ledger.request_search(
                self.patient_id, req.doctor_id, commitment, req.nonce,
                # A and C keep PPSEB's public, on-chain trapdoor.
                public_token=req.token if self.mode in ("A", "C") else None,
            )
            if nullifier is not None:
                self.ledger.add_nullifier(nullifier)
        self._last_nonce[req.doctor_id] = req.nonce
        trace.decision(
            "All gates passed — searching",
            verdict="ACCEPTED",
            evidence={"mode": self.mode, "nonce": req.nonce, "epoch": req.epoch,
                      "commitment": commitment.hex()[:16]},
            algo="Gateway",
            highlight=True,
        )

        record_ids = self.search_node.search(req.token, req.doctor_id, req.epoch,
                                             self.index)
        trace.result(
            f"{len(record_ids)} record(s) matched",
            data={"record_ids": record_ids, "keyword_len": len(req.keyword)},
            algo="SearchNode",
        )
        return SearchResult(ok=True, reason="accepted", record_ids=record_ids,
                            trace=trace.to_list())

    def _resolve_key(self, doctor_id: str) -> VerifyKey | None:
        if self._key_resolver is None:
            return None
        return self._key_resolver(doctor_id)

    def _reject(self, trace: Trace, reason: str, detail: str) -> SearchResult:
        trace.decision(
            f"Search rejected: {reason}",
            verdict="REJECTED",
            evidence={"reason": reason, "mode": self.mode},
            detail=detail,
            algo="Gateway",
            highlight=True,
        )
        return SearchResult(ok=False, reason=reason, record_ids=[],
                            trace=trace.to_list())

    # -- retrieval --------------------------------------------------------
    def authorize_retrieval(self, req: RetrievalRequest) -> RetrievalAuthorisation:
        """Gate one record fetch.

        Both modes need a live grant at the current epoch, in scope. Mode B also
        checks the doctor's signature and spends a nonce from the same counter
        as searches, so a captured retrieval cannot be replayed (deck finding 7).
        Mode A keeps PPSEB's behaviour: no requester authentication. As with
        search, the nonce is committed only after every gate passes.
        """
        gates = GATE_POLICY[self.mode]
        if "signature" in gates:
            verify_key = self._resolve_key(req.doctor_id)
            message = retrieval_signing_message(req.record_id, req.nonce, req.epoch,
                                                req.timestamp)
            if verify_key is None or not verify_key.verify(req.signature, message):
                return RetrievalAuthorisation(False, "bad_signature",
                                              f"retrieval of {req.record_id} "
                                              f"for {req.doctor_id}")
        current_epoch = self.ledger.current_epoch(self.patient_id)
        if req.epoch != current_epoch:
            return RetrievalAuthorisation(False, "stale_epoch",
                                          f"capability epoch {req.epoch}, "
                                          f"patient epoch {current_epoch}")
        if "nonce" in gates:
            last = self.last_nonce(req.doctor_id)
            if req.nonce <= last:
                return RetrievalAuthorisation(False, "reused_nonce",
                                              f"nonce {req.nonce} <= last accepted {last}")
        if not self.ledger.is_authorized(req.doctor_id, req.record_id):
            return RetrievalAuthorisation(False, "out_of_scope",
                                          f"{req.record_id} is not in "
                                          f"{req.doctor_id}'s scope")
        if "nonce" in gates:
            self._last_nonce[req.doctor_id] = req.nonce
        return RetrievalAuthorisation(True, "authorized")

    def reset_nonces(self) -> None:
        """Test/demo hook: forget accepted nonces (never used mid-demo)."""
        self._last_nonce.clear()
