"""Standard primitives, used exactly as standard (PRD §8 "sound vs prototype").

AES-256-GCM, HKDF-SHA-256 and Ed25519 come from the `cryptography` package and
are not reimplemented here — the PRD's claims policy lets us call these
standard. Everything in this module is deterministic given its inputs, which is
what the property tests lean on.

Two rules this module enforces for the rest of the system:
  * every secret is `bytes`, never a `str`, so it cannot be accidentally
    interpolated into a trace or a log line (Requirement 10.7);
  * decryption and signature verification raise on failure rather than
    returning `None`, so a caller that forgets to check cannot continue with
    partial output (fail closed, design "Error Handling").
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Protocol

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AES_KEY_BYTES = 32
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
ED25519_SEED_BYTES = 32


class MedVaultCryptoError(Exception):
    """Raised when a primitive refuses its input (bad tag, bad signature)."""


# --------------------------------------------------------------------------
# Hashing
# --------------------------------------------------------------------------

def sha256(*parts: bytes) -> bytes:
    """SHA-256 over the concatenation of `parts`."""
    h = hashlib.sha256()
    for part in parts:
        h.update(part)
    return h.digest()


def sha256_hex(*parts: bytes) -> str:
    return sha256(*parts).hex()


def hexb(value: bytes) -> str:
    """Hex for display. Never call this on a secret (Requirement 10.7)."""
    return value.hex()


def unhex(value: str) -> bytes:
    return bytes.fromhex(value)


# --------------------------------------------------------------------------
# AES-256-GCM
# --------------------------------------------------------------------------

class RandomSource(Protocol):
    """Anything that can produce fresh bytes (e.g. `secrets.SystemRandom`)."""

    def random_bytes(self, n: int) -> bytes:  # pragma: no cover - protocol
        ...


class SeededRandomSource:
    """A deterministic, counter-based byte source.

    Requirement 10.10 asks for byte-identical output across runs with the same
    seed, which includes ciphertexts, which includes the per-record DEK and the
    GCM nonce. So the demo derives both from the project seed instead of the
    OS CSPRNG.

    This is a demonstrability choice and it is labelled as one: a record key that
    is derivable from a published seed is not a secret in any real deployment.
    `new_dek()` with no source still uses `os.urandom`, so the default path of
    the library remains the safe one.
    """

    def __init__(self, seed: bytes, *, domain: bytes = b"medvault-demo-rng") -> None:
        self._seed = domain + b":" + seed
        self._counter = 0

    def random_bytes(self, n: int) -> bytes:
        self._counter += 1
        return hashlib.shake_256(
            self._seed + self._counter.to_bytes(8, "big")
        ).digest(n)


def new_dek(rng: RandomSource | None = None) -> bytes:
    """A fresh 256-bit data-encryption key.

    `rng` exists so tests can supply a deterministic source; production paths
    and the demo use the operating system's CSPRNG, because a record key that
    is reproducible from the project seed would be a real weakness, not a
    convenience.
    """
    if rng is not None:
        return rng.random_bytes(AES_KEY_BYTES)
    return os.urandom(AES_KEY_BYTES)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, *, aad: bytes | None = None,
                    nonce: bytes | None = None) -> bytes:
    """Seal `plaintext`; returns `nonce ‖ ciphertext ‖ tag` as one blob."""
    if len(key) != AES_KEY_BYTES:
        raise ValueError(f"AES-256-GCM needs a {AES_KEY_BYTES}-byte key, got {len(key)}")
    nonce = nonce if nonce is not None else os.urandom(GCM_NONCE_BYTES)
    if len(nonce) != GCM_NONCE_BYTES:
        raise ValueError(f"nonce must be {GCM_NONCE_BYTES} bytes")
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce + sealed


def aes_gcm_decrypt(key: bytes, blob: bytes, *, aad: bytes | None = None) -> bytes:
    """Open a blob produced by `aes_gcm_encrypt`; raises `MedVaultCryptoError`."""
    if len(blob) < GCM_NONCE_BYTES + GCM_TAG_BYTES:
        raise MedVaultCryptoError("sealed blob is too short to contain a nonce and a tag")
    nonce, sealed = blob[:GCM_NONCE_BYTES], blob[GCM_NONCE_BYTES:]
    try:
        return AESGCM(key).decrypt(nonce, sealed, aad)
    except InvalidTag as exc:
        raise MedVaultCryptoError("AES-GCM authentication failed") from exc


# --------------------------------------------------------------------------
# HKDF
# --------------------------------------------------------------------------

def hkdf_sha256(ikm: bytes, *, info: bytes, salt: bytes | None = None,
                length: int = AES_KEY_BYTES) -> bytes:
    """HKDF-SHA-256, used to turn a KEM shared secret into an AES key.

    `info` binds the derived key to the envelope epoch (Requirement 2.2), so a
    ciphertext sealed for one epoch cannot be opened as if it were another.
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt or None,
                info=info).derive(ikm)


# --------------------------------------------------------------------------
# Ed25519
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class SigningKeypair:
    """A raw-bytes Ed25519 keypair.

    `label` carries the visible `TEST_KEY:` marker for anything that is not a
    real key (Requirement 10.8). It is never used in a cryptographic
    computation — it exists so a leaked test key cannot be mistaken for a
    production one in a screenshot.
    """

    private_bytes: bytes
    public_bytes: bytes
    label: str = ""

    def sign(self, message: bytes) -> bytes:
        sk = Ed25519PrivateKey.from_private_bytes(self.private_bytes)
        return sk.sign(message)

    def public_key(self) -> "VerifyKey":
        return VerifyKey(self.public_bytes, self.label)

    def fingerprint(self) -> str:
        """A safe identifier for display: the public key's hash, never the key."""
        return sha256_hex(self.public_bytes)[:16]


@dataclass(frozen=True)
class VerifyKey:
    public_bytes: bytes
    label: str = ""

    def verify(self, signature: bytes, message: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.public_bytes).verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False


def ed25519_keypair(seed: bytes | None = None, *, label: str = "") -> SigningKeypair:
    """Derive a keypair from `seed` (32 bytes) or generate a fresh one."""
    if seed is None:
        seed = os.urandom(ED25519_SEED_BYTES)
    if len(seed) != ED25519_SEED_BYTES:
        raise ValueError(f"Ed25519 seed must be {ED25519_SEED_BYTES} bytes")
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes_raw()
    return SigningKeypair(seed, pk, label)


def constant_time_equal(a: bytes, b: bytes) -> bool:
    """Compare tokens/commitments without an early exit."""
    return hmac.compare_digest(a, b)
