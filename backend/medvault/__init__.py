"""MedVault-PQ — the system layer built on top of the PPSEB research code.

The `ppseb/` and `attacks/` packages are the research baseline and attack
target. They are imported, never modified: `medvault/` wraps them so the same
algorithm runs under the demo's consent, epoch, nonce and Merkle gates.

Module map (design.md M1-M9):
  crypto.py       AES-256-GCM, HKDF-SHA-256, Ed25519, hashing helpers
  merkle.py       SHA-256 Merkle tree over a patient's records
  blob_store.py   content-addressed ciphertext store + evil-cloud modes
  kem.py          KEMWrapper: liboqs ML-KEM-768, or the pure-Python fallback
  envelope.py     Capability / Envelope wrap-unwrap (ML-KEM + HKDF + AES-GCM)
  search.py       SearchIndex modes A/B, keyed tokens, SearchNode, signatures
  consent.py      ConsentLedger: doctors, grants, epochs, audit events
  gateway.py      the gate sequence: signature, epoch, nonce, scope, proof
  service.py      one in-process demo session tying the modules together
  repro.py        headline attack + cost numbers, written as JSON
"""

from __future__ import annotations

__all__ = [
    "config",
    "crypto",
    "merkle",
    "blob_store",
    "kem",
    "envelope",
    "search",
    "consent",
    "gateway",
    "service",
    "repro",
]
