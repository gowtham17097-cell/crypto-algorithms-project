"""
test_aes.py
------------
Unit tests for src/aes_cipher.py

Run with:
    python -m unittest discover tests
"""

import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.aes_cipher import (
    generate_key,
    encrypt,
    decrypt,
    encrypt_string,
    decrypt_to_string,
    KEY_SIZE_BYTES,
    NONCE_SIZE_BYTES,
)


class TestAesCipher(unittest.TestCase):

    def test_generate_key_correct_length(self):
        key = generate_key()
        self.assertEqual(len(key), KEY_SIZE_BYTES)

    def test_generate_key_is_random(self):
        """Two generated keys should (essentially never) collide."""
        key1 = generate_key()
        key2 = generate_key()
        self.assertNotEqual(key1, key2)

    def test_encrypt_decrypt_roundtrip(self):
        key = generate_key()
        plaintext = b"a secret message"
        result = encrypt(plaintext, key)
        decrypted = decrypt(result["nonce"], result["ciphertext"], result["tag"], key)
        self.assertEqual(decrypted, plaintext)

    def test_encrypt_string_decrypt_to_string_roundtrip(self):
        key = generate_key()
        text = "Hello, AES!"
        result = encrypt_string(text, key)
        decrypted = decrypt_to_string(result["nonce"], result["ciphertext"], result["tag"], key)
        self.assertEqual(decrypted, text)

    def test_nonce_has_correct_length(self):
        key = generate_key()
        result = encrypt(b"data", key)
        self.assertEqual(len(result["nonce"]), NONCE_SIZE_BYTES)

    def test_same_plaintext_different_ciphertext(self):
        """Encrypting the same plaintext twice must give different output,
        since a fresh random nonce is used each time. Reusing nonces would
        be a serious security bug in GCM mode."""
        key = generate_key()
        result1 = encrypt(b"identical message", key)
        result2 = encrypt(b"identical message", key)
        self.assertNotEqual(result1["nonce"], result2["nonce"])
        self.assertNotEqual(result1["ciphertext"], result2["ciphertext"])

    def test_decrypt_with_wrong_key_fails(self):
        key_a = generate_key()
        key_b = generate_key()
        result = encrypt(b"top secret", key_a)
        with self.assertRaises(ValueError):
            decrypt(result["nonce"], result["ciphertext"], result["tag"], key_b)

    def test_tampered_ciphertext_detected(self):
        key = generate_key()
        result = encrypt(b"do not modify this", key)
        tampered = bytearray(result["ciphertext"])
        tampered[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decrypt(result["nonce"], bytes(tampered), result["tag"], key)

    def test_tampered_tag_detected(self):
        key = generate_key()
        result = encrypt(b"do not modify this either", key)
        tampered_tag = bytearray(result["tag"])
        tampered_tag[0] ^= 0xFF
        with self.assertRaises(ValueError):
            decrypt(result["nonce"], result["ciphertext"], bytes(tampered_tag), key)

    def test_wrong_key_size_raises_on_encrypt(self):
        with self.assertRaises(ValueError):
            encrypt(b"data", b"too short a key")

    def test_wrong_key_size_raises_on_decrypt(self):
        key = generate_key()
        result = encrypt(b"data", key)
        with self.assertRaises(ValueError):
            decrypt(result["nonce"], result["ciphertext"], result["tag"], b"too short a key")


if __name__ == "__main__":
    unittest.main()
