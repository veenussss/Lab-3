"""Pure crypto functions (no I/O)."""
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16
AES_OVERHEAD = NONCE_LEN + TAG_LEN  # 28


def sha256(*parts: bytes) -> bytes:
    h = hashes.Hash(hashes.SHA256())
    for p in parts:
        h.update(p)
    return h.finalize()


def custom_hmac(key: bytes, data: bytes) -> bytes:
    """Course HMAC: SHA256(Ko || SHA256(Ki || x)), 32-byte Ki/Ko, no padding.

    Deliberately NOT standard HMAC.
    """
    if len(key) != KEY_LEN:
        raise ValueError("HMAC key must be 32 bytes")
    ki = bytes(b ^ 0x36 for b in key)
    ko = bytes(b ^ 0x5C for b in key)
    inner = sha256(ki, data)
    return sha256(ko, inner)


def aes_encrypt(key: bytes, plaintext: bytes, nonce: bytes | None = None) -> bytes:
    """Return nonce || ciphertext || tag. `nonce` is for tests only."""
    if len(key) != KEY_LEN:
        raise ValueError("AES key must be 32 bytes")
    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    elif len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 12 bytes")
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def aes_decrypt(key: bytes, blob: bytes) -> bytes:
    """Local decryption (tests / diagnostics). Raises InvalidTag on tampering."""
    if len(key) != KEY_LEN:
        raise ValueError("AES key must be 32 bytes")
    if len(blob) < AES_OVERHEAD:
        raise ValueError("blob shorter than 28 bytes")
    return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], None)
