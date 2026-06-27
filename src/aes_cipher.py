"""
aes_cipher.py
--------------
AES symmetric encryption using GCM mode (authenticated encryption).

WHY AES-GCM:
AES is a SYMMETRIC cipher - the same key is used to encrypt and decrypt.
It's fast, so it's the standard choice for bulk data (files, disk volumes,
TLS session traffic).

Plain AES (e.g. ECB or CBC mode) only gives you CONFIDENTIALITY - it hides
the data, but an attacker can still tamper with the ciphertext and you'd
have no way to know. GCM mode adds an AUTHENTICATION TAG on top, so any
tampering with the ciphertext (even flipping a single bit) is detected on
decryption. This combination is called "authenticated encryption" (AEAD).

KEY CONCEPTS:
    key   - 256-bit (32 byte) secret shared between sender and receiver.
            Must never be transmitted in plaintext or reused across unrelated
            messages without care.
    nonce - a 96-bit (12 byte) "number used once". Must NEVER be reused with
            the same key, or it completely breaks GCM's security guarantees.
            A fresh random nonce is generated for every encryption call.
    tag   - a 128-bit authentication tag produced during encryption and
            checked during decryption. If the ciphertext (or the tag itself)
            was modified, decryption raises an error instead of returning
            corrupted plaintext.

This module uses PyCryptodome's `Crypto.Cipher.AES` in MODE_GCM.
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_SIZE_BYTES = 32   # AES-256
NONCE_SIZE_BYTES = 12  # 96 bits, the recommended size for GCM


def generate_key() -> bytes:
    """Generate a new random 256-bit AES key."""
    return get_random_bytes(KEY_SIZE_BYTES)


def encrypt(plaintext: bytes, key: bytes) -> dict:
    """
    Encrypt data with AES-256-GCM.

    Args:
        plaintext: The raw bytes to encrypt.
        key: A 32-byte secret key (see generate_key()).

    Returns:
        A dict with 'nonce', 'ciphertext', and 'tag', each as bytes.
        All three are needed to decrypt later - none of them are secret
        except the key itself, so it's safe to store/transmit nonce+tag
        alongside the ciphertext.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes, got {len(key)}.")

    nonce = get_random_bytes(NONCE_SIZE_BYTES)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {"nonce": nonce, "ciphertext": ciphertext, "tag": tag}


def decrypt(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    """
    Decrypt data with AES-256-GCM, verifying the authentication tag.

    Raises:
        ValueError: if the key is the wrong size, OR if the ciphertext/tag
            has been tampered with (this is GCM's built-in integrity check -
            it's not just "wrong key", it actively detects corruption).

    Returns:
        The original plaintext bytes.
    """
    if len(key) != KEY_SIZE_BYTES:
        raise ValueError(f"Key must be {KEY_SIZE_BYTES} bytes, got {len(key)}.")

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    # verify_and_decrypt raises ValueError ("MAC check failed") if the
    # ciphertext or tag don't match - this is the tamper detection.
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


def encrypt_string(text: str, key: bytes) -> dict:
    """Convenience wrapper: encrypt a UTF-8 string instead of raw bytes."""
    return encrypt(text.encode("utf-8"), key)


def decrypt_to_string(nonce: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> str:
    """Convenience wrapper: decrypt and decode back to a UTF-8 string."""
    return decrypt(nonce, ciphertext, tag, key).decode("utf-8")
