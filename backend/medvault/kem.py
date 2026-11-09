"""ML-KEM-768 (FIPS 203) capability wrapping — with a labelled fallback.

Requirement 2.1 and 2.6. `get_kem_wrapper()` prefers a real library
(`liboqs-python`) and falls back to `PurePythonMLKEM`, whose `label()` says
`NON-HARDENED` out loud. That label is not decoration: it appears in the
envelope metadata, in traces, and in every result file, so no screenshot can
be mistaken for a side-channel-hardened deployment.

What the fallback is and is not
-------------------------------
* It implements the FIPS 203 algorithms — K-PKE key generation, encryption and
  decryption, the FO transform with implicit rejection, KDF/PRF/Hash XOFs from
  `hashlib`'s SHA-3 family, and the standard byte encoding/compression.
* Polynomial multiplication uses a schoolbook negacyclic convolution instead of
  the NTT. That is an implementation choice inside R_q, not a change to the
  scheme: the arithmetic is identical, only slower.
* It is **not** constant-time and has **not** been checked against the official
  NIST known-answer test vectors, because the demo laptop is offline. What is
  tested here is round-trip correctness, implicit rejection under a modified
  ciphertext, determinism under a fixed seed, and the published key/ciphertext
  sizes.

That is the honest claim available: the envelope is protected by ML-KEM, and
the implementation backing it in this demo is a non-hardened one.
"""

from __future__ import annotations

import hashlib
import os
from abc import ABC, abstractmethod

import numpy as np

ML_KEM_768_PARAMS = {"k": 3, "n": 256, "q": 3329, "eta1": 2, "eta2": 2, "du": 10, "dv": 4}

# Published sizes for ML-KEM-768 (FIPS 203 Table 3).
ML_KEM_768_PUBLIC_KEY_BYTES = 1184
ML_KEM_768_SECRET_KEY_BYTES = 2400
ML_KEM_768_CIPHERTEXT_BYTES = 1088
ML_KEM_768_SHARED_SECRET_BYTES = 32

_LABEL_LIBOQS = "liboqs-ml-kem-768"
_LABEL_PURE = "pure-python-ml-kem-768-NON-HARDENED"


class KEMWrapper(ABC):
    """The interface the envelope layer sees. Nothing else is allowed."""

    @abstractmethod
    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        """Return `(public_key, secret_key)`."""

    @abstractmethod
    def encaps(self, public_key: bytes, seed: bytes | None = None) -> tuple[bytes, bytes]:
        """Return `(ciphertext, shared_secret)`."""

    @abstractmethod
    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Return the shared secret. Never raises: a wrong key yields wrong bytes."""

    @abstractmethod
    def label(self) -> str:
        """Which implementation is actually backing this session."""


# ==========================================================================
# Pure-Python ML-KEM-768
# ==========================================================================

_Q = 3329
_N = 256
_K = 3
_ETA1 = 2
_ETA2 = 2
_DU = 10
_DV = 4


def _g(seed: bytes) -> tuple[bytes, bytes]:
    """G = SHA3-512, split into two 32-byte halves."""
    digest = hashlib.sha3_512(seed).digest()
    return digest[:32], digest[32:]


def _h(data: bytes) -> bytes:
    """H = SHA3-256."""
    return hashlib.sha3_256(data).digest()


def _j(data: bytes) -> bytes:
    """J = SHAKE256 with a 32-byte output."""
    return hashlib.shake_256(data).digest(32)


def _prf(seed: bytes, counter: int, length: int) -> bytes:
    """PRF(s, b) = SHAKE256(s ‖ b, length)."""
    return hashlib.shake_256(seed + bytes([counter % 256])).digest(length)


def _sample_ntt(seed: bytes) -> np.ndarray:
    """Rejection-sample 256 uniform coefficients in [0, q) from SHAKE128.

    Named for the NTT domain it feeds in the reference implementation; here the
    output is used directly in the coefficient domain.
    """
    xof = hashlib.shake_128(seed)
    out: list[int] = []
    consumed = 0
    stream = b""
    while len(out) < _N:
        stream = xof.digest(consumed + 168)
        block = stream[consumed:]
        consumed += 168
        for i in range(0, 168, 3):
            d1 = block[i] | ((block[i + 1] & 0x0F) << 8)
            d2 = (block[i + 1] >> 4) | (block[i + 2] << 4)
            if d1 < _Q and len(out) < _N:
                out.append(d1)
            if d2 < _Q and len(out) < _N:
                out.append(d2)
    return np.array(out, dtype=np.int64)


def _sample_cbd2(buf: bytes) -> np.ndarray:
    """SamplePolyCBD_2: 128 bytes -> 256 coefficients in {-2..2}, reduced mod q.

    The reduction is not cosmetic: `s` is serialised with `_byte_encode`, which
    packs a fixed-width integer, and a coefficient of -2 would be packed as the
    two's-complement 4094 rather than 3327 = -2 mod 3329. Decoding would then
    reconstruct a different polynomial than the one the key was built with, and
    every decapsulation would fail.
    """
    coeffs = np.zeros(_N, dtype=np.int64)
    for i in range(_N // 8):
        word = int.from_bytes(buf[4 * i:4 * i + 4], "little")
        nibbles = word & 0x55555555
        nibbles += (word >> 1) & 0x55555555
        for j in range(8):
            a = (nibbles >> (4 * j)) & 0x3
            b = (nibbles >> (4 * j + 2)) & 0x3
            coeffs[8 * i + j] = a - b
    return coeffs % _Q


def _byte_encode(coeffs: np.ndarray, d: int) -> bytes:
    """ByteEncode_d: pack 256 d-bit coefficients, little-endian bit order."""
    value = 0
    mask = (1 << d) - 1
    for i, c in enumerate(coeffs):
        value |= (int(c) & mask) << (i * d)
    return value.to_bytes(32 * d, "little")


def _byte_decode(data: bytes, d: int) -> np.ndarray:
    """ByteDecode_d: the inverse of `_byte_encode`."""
    value = int.from_bytes(data, "little")
    mask = (1 << d) - 1
    return np.array([(value >> (i * d)) & mask for i in range(_N)], dtype=np.int64)


def _compress(coeffs: np.ndarray, d: int) -> np.ndarray:
    """Compress_d(x) = round(2^d / q · x) mod 2^d, in exact integer arithmetic."""
    modulus = 1 << d
    return ((coeffs * modulus * 2 + _Q) // (2 * _Q)) % modulus


def _decompress(coeffs: np.ndarray, d: int) -> np.ndarray:
    """Decompress_d(y) = round(q / 2^d · y)."""
    return (_Q * coeffs + (1 << (d - 1))) >> d


def _poly_mul(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    """Negacyclic convolution in R_q = Z_q[x]/(x^256 + 1).

    The reference implementation multiplies through the NTT. This is the same
    product computed directly: `convolve` then fold the wrap-around half back
    with a sign flip. Slower, identical value.
    """
    conv = np.convolve(a.astype(np.int64), b.astype(np.int64))
    low = conv[:_N]
    high = np.zeros(_N, dtype=np.int64)
    high[:len(conv) - _N] = conv[_N:]
    return (low - high) % _Q


def _poly_add(a: np.ndarray, b: np.ndarray) -> np.ndarray:
    return (a + b) % _Q


def _gen_matrix(rho: bytes) -> list[list[np.ndarray]]:
    """Â[i][j] = SampleNTT(ρ ‖ j ‖ i), matching FIPS 203 Algorithm 13."""
    return [[_sample_ntt(rho + bytes([j]) + bytes([i])) for j in range(_K)]
            for i in range(_K)]


def _k_pke_keygen(d: bytes) -> tuple[bytes, bytes]:
    """K-PKE.KeyGen (FIPS 203 Algorithm 13)."""
    rho, sigma = _g(d + bytes([_K]))
    matrix = _gen_matrix(rho)

    counter = 0
    s = []
    for _ in range(_K):
        s.append(_sample_cbd2(_prf(sigma, counter, 64 * _ETA1)))
        counter += 1
    e = []
    for _ in range(_K):
        e.append(_sample_cbd2(_prf(sigma, counter, 64 * _ETA1)))
        counter += 1

    t = []
    for i in range(_K):
        acc = e[i].copy()
        for j in range(_K):
            acc = (acc + _poly_mul(matrix[i][j], s[j])) % _Q
        t.append(acc)

    ek = b"".join(_byte_encode(p, 12) for p in t) + rho
    dk = b"".join(_byte_encode(p, 12) for p in s)
    return ek, dk


def _k_pke_encrypt(ek: bytes, message: bytes, r: bytes) -> bytes:
    """K-PKE.Encrypt (FIPS 203 Algorithm 14)."""
    split = 384 * _K
    t = [_byte_decode(ek[i * 384:(i + 1) * 384], 12) for i in range(_K)]
    rho = ek[split:split + 32]
    matrix = _gen_matrix(rho)

    counter = 0
    r_vec = []
    for _ in range(_K):
        r_vec.append(_sample_cbd2(_prf(r, counter, 64 * _ETA1)))
        counter += 1
    e1 = []
    for _ in range(_K):
        e1.append(_sample_cbd2(_prf(r, counter, 64 * _ETA2)))
        counter += 1
    e2 = _sample_cbd2(_prf(r, counter, 64 * _ETA2))

    # u = A^T · r + e1  (transpose: row i of A^T is column i of A)
    u = []
    for i in range(_K):
        acc = e1[i].copy()
        for j in range(_K):
            acc = (acc + _poly_mul(matrix[j][i], r_vec[j])) % _Q
        u.append(acc)

    mu = _decompress(_byte_decode(message, 1), 1)
    v = e2.copy()
    for i in range(_K):
        v = (v + _poly_mul(t[i], r_vec[i])) % _Q
    v = (v + mu) % _Q

    c1 = b"".join(_byte_encode(_compress(p, _DU), _DU) for p in u)
    c2 = _byte_encode(_compress(v, _DV), _DV)
    return c1 + c2


def _k_pke_decrypt(dk_pke: bytes, ciphertext: bytes) -> bytes:
    """K-PKE.Decrypt (FIPS 203 Algorithm 15)."""
    s = [_byte_decode(dk_pke[i * 384:(i + 1) * 384], 12) for i in range(_K)]
    c1_len = 32 * _DU * _K
    c1, c2 = ciphertext[:c1_len], ciphertext[c1_len:]
    u = [_decompress(_byte_decode(c1[i * 32 * _DU:(i + 1) * 32 * _DU], _DU), _DU)
         for i in range(_K)]
    v = _decompress(_byte_decode(c2, _DV), _DV)

    w = v.copy()
    for i in range(_K):
        w = (w - _poly_mul(s[i], u[i])) % _Q
    return _byte_encode(_compress(w, 1), 1)


class PurePythonMLKEM(KEMWrapper):
    """ML-KEM-768 in pure Python. Correct, deterministic, not constant-time."""

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        d = seed if seed is not None else os.urandom(32)
        z = _h(d + b"implicit-rejection") if seed is not None else os.urandom(32)
        if len(d) != 32:
            raise ValueError("ML-KEM keygen seed must be 32 bytes")
        ek_pke, dk_pke = _k_pke_keygen(d)
        ek = ek_pke
        dk = dk_pke + ek + _h(ek) + z
        return ek, dk

    def encaps(self, public_key: bytes, seed: bytes | None = None) -> tuple[bytes, bytes]:
        if len(public_key) != ML_KEM_768_PUBLIC_KEY_BYTES:
            raise ValueError(
                f"ML-KEM-768 public key must be {ML_KEM_768_PUBLIC_KEY_BYTES} bytes, "
                f"got {len(public_key)}"
            )
        m = seed if seed is not None else os.urandom(32)
        if len(m) != 32:
            raise ValueError("ML-KEM encapsulation seed must be 32 bytes")
        key, r = _g(m + _h(public_key))
        ciphertext = _k_pke_encrypt(public_key, m, r)
        return ciphertext, key

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate, with implicit rejection.

        A wrong secret key or a modified ciphertext does *not* raise: it returns
        a pseudorandom key derived from `z`. The envelope layer's AES-GCM tag is
        what turns that into a hard failure (Requirement 2.4/2.5), which is
        exactly how ML-KEM is meant to compose with a DEM.
        """
        if len(secret_key) != ML_KEM_768_SECRET_KEY_BYTES:
            raise ValueError(
                f"ML-KEM-768 secret key must be {ML_KEM_768_SECRET_KEY_BYTES} bytes, "
                f"got {len(secret_key)}"
            )
        if len(ciphertext) != ML_KEM_768_CIPHERTEXT_BYTES:
            raise ValueError(
                f"ML-KEM-768 ciphertext must be {ML_KEM_768_CIPHERTEXT_BYTES} bytes, "
                f"got {len(ciphertext)}"
            )
        split = 384 * _K
        dk_pke = secret_key[:split]
        ek_pke = secret_key[split:split + ML_KEM_768_PUBLIC_KEY_BYTES]
        h = secret_key[split + ML_KEM_768_PUBLIC_KEY_BYTES:split + ML_KEM_768_PUBLIC_KEY_BYTES + 32]
        z = secret_key[split + ML_KEM_768_PUBLIC_KEY_BYTES + 32:]

        m_prime = _k_pke_decrypt(dk_pke, ciphertext)
        key_prime, r_prime = _g(m_prime + h)
        rejection_key = _j(z + ciphertext)
        ciphertext_prime = _k_pke_encrypt(ek_pke, m_prime, r_prime)
        return key_prime if ciphertext_prime == ciphertext else rejection_key

    def label(self) -> str:
        return _LABEL_PURE


# ==========================================================================
# liboqs, when it happens to be installed
# ==========================================================================

class LibOQSWrapper(KEMWrapper):
    """ML-KEM-768 via liboqs-python. Used only when the import succeeds."""

    def __init__(self) -> None:
        import oqs  # noqa: F401  (import check happens in get_kem_wrapper)

        self._oqs = oqs

    def keygen(self, seed: bytes | None = None) -> tuple[bytes, bytes]:
        if seed is not None:
            raise ValueError("liboqs keygen does not accept a caller-supplied seed")
        with self._oqs.KeyEncapsulation("ML-KEM-768") as kem:
            public_key = kem.generate_keypair()
            return public_key, kem.export_secret_key()

    def encaps(self, public_key: bytes, seed: bytes | None = None) -> tuple[bytes, bytes]:
        if seed is not None:
            raise ValueError("liboqs encapsulation does not accept a caller-supplied seed")
        with self._oqs.KeyEncapsulation("ML-KEM-768") as kem:
            return kem.encap_secret(public_key)

    def decaps(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        with self._oqs.KeyEncapsulation("ML-KEM-768", secret_key) as kem:
            return kem.decap_secret(ciphertext)

    def label(self) -> str:
        return _LABEL_LIBOQS


_CACHED_WRAPPER: KEMWrapper | None = None


def get_kem_wrapper() -> KEMWrapper:
    """Probe liboqs once, then hand out the same wrapper for the session."""
    global _CACHED_WRAPPER
    if _CACHED_WRAPPER is not None:
        return _CACHED_WRAPPER
    try:
        _CACHED_WRAPPER = LibOQSWrapper()
    except Exception:
        _CACHED_WRAPPER = PurePythonMLKEM()
    return _CACHED_WRAPPER


def reset_kem_wrapper_cache() -> None:
    """Test hook: forget the probe result."""
    global _CACHED_WRAPPER
    _CACHED_WRAPPER = None


def size_report(wrapper: KEMWrapper | None = None) -> dict:
    """Published ML-KEM-768 sizes, for the evaluation table."""
    return {
        "label": (wrapper or get_kem_wrapper()).label(),
        "public_key_bytes": ML_KEM_768_PUBLIC_KEY_BYTES,
        "secret_key_bytes": ML_KEM_768_SECRET_KEY_BYTES,
        "ciphertext_bytes": ML_KEM_768_CIPHERTEXT_BYTES,
        "shared_secret_bytes": ML_KEM_768_SHARED_SECRET_BYTES,
    }
