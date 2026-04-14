"""
AES-256-GCM encryption/decryption for vault secrets.
Nonce (12 bytes) is stored alongside ciphertext+tag as: nonce || ciphertext || tag
All stored as raw bytes in SQLite BLOB columns.
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Returns (nonce, ciphertext_with_tag).
    Store both; pass both to decrypt().
    """
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext


def decrypt(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    """Decrypt and return the original plaintext string."""
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode("utf-8")
