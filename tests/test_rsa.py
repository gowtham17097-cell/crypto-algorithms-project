"""
test_rsa.py
------------
Unit tests for src/rsa_cipher.py

Note: RSA key generation is computationally expensive, so this suite
generates ONE key pair in setUpClass() and reuses it across all test
methods, rather than generating a fresh pair per test.

Run with:
    python -m unittest discover tests
"""

import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.rsa_cipher import (
    generate_keypair,
    export_private_key,
    export_public_key,
    load_private_key,
    load_public_key,
    encrypt,
    decrypt,
    sign,
    verify,
)


class TestRsaCipher(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Use a smaller key size than the 2048-bit default purely to keep
        # the test suite fast - 1024 bits is NOT secure for real use, but
        # is fine for exercising the logic in tests.
        cls.private_key, cls.public_key = generate_keypair(key_size=1024)

    def test_generate_keypair_default_size(self):
        private_key, public_key = generate_keypair()
        self.assertEqual(private_key.size_in_bits(), 2048)
        self.assertEqual(public_key.size_in_bits(), 2048)

    def test_export_and_load_private_key_roundtrip(self):
        pem = export_private_key(self.private_key)
        loaded = load_private_key(pem)
        self.assertEqual(loaded.export_key(), pem)

    def test_export_and_load_public_key_roundtrip(self):
        pem = export_public_key(self.public_key)
        loaded = load_public_key(pem)
        self.assertEqual(loaded.export_key(), pem)

    def test_encrypt_decrypt_roundtrip(self):
        message = b"a short secret"
        ciphertext = encrypt(message, self.public_key)
        decrypted = decrypt(ciphertext, self.private_key)
        self.assertEqual(decrypted, message)

    def test_encrypt_produces_different_ciphertext_each_time(self):
        """OAEP padding is randomized, so encrypting the same message twice
        should not produce identical ciphertext."""
        message = b"identical message"
        c1 = encrypt(message, self.public_key)
        c2 = encrypt(message, self.public_key)
        self.assertNotEqual(c1, c2)

    def test_decrypt_with_wrong_private_key_fails(self):
        other_private, _ = generate_keypair(key_size=1024)
        ciphertext = encrypt(b"secret", self.public_key)
        with self.assertRaises(ValueError):
            decrypt(ciphertext, other_private)

    def test_sign_and_verify_valid_signature(self):
        message = b"this message is authentic"
        signature = sign(message, self.private_key)
        self.assertTrue(verify(message, signature, self.public_key))

    def test_verify_fails_for_tampered_message(self):
        message = b"original message"
        tampered = b"tampered message"
        signature = sign(message, self.private_key)
        self.assertFalse(verify(tampered, signature, self.public_key))

    def test_verify_fails_for_wrong_public_key(self):
        _, other_public = generate_keypair(key_size=1024)
        message = b"signed with one key, checked with another"
        signature = sign(message, self.private_key)
        self.assertFalse(verify(message, signature, other_public))

    def test_verify_returns_false_not_raise_for_garbage_signature(self):
        message = b"some message"
        garbage_signature = b"not a real signature at all"
        # Should return False, not raise an exception
        self.assertFalse(verify(message, garbage_signature, self.public_key))


if __name__ == "__main__":
    unittest.main()
