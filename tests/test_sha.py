"""
test_sha.py
------------
Unit tests for src/sha_hash.py

Run with:
    python -m unittest discover tests
"""

import sys
import unittest
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.sha_hash import hash_string, hash_file, verify_integrity


class TestShaHash(unittest.TestCase):

    def test_hash_string_is_deterministic(self):
        """Hashing the same input twice must give the same result."""
        h1 = hash_string("hello world")
        h2 = hash_string("hello world")
        self.assertEqual(h1, h2)

    def test_different_input_gives_different_hash(self):
        h1 = hash_string("hello world")
        h2 = hash_string("hello world!")
        self.assertNotEqual(h1, h2)

    def test_sha256_output_length(self):
        digest = hash_string("test", "sha256")
        self.assertEqual(len(digest), 64)  # 256 bits = 64 hex chars

    def test_sha512_output_length(self):
        digest = hash_string("test", "sha512")
        self.assertEqual(len(digest), 128)  # 512 bits = 128 hex chars

    def test_invalid_algorithm_raises(self):
        with self.assertRaises(ValueError):
            hash_string("test", "md5")  # not in our supported list

    def test_hash_file_matches_known_content(self):
        tmp_file = Path(__file__).resolve().parent / "_tmp_test_file.txt"
        tmp_file.write_text("fixed content for testing")
        try:
            file_hash = hash_file(str(tmp_file))
            string_hash = hash_string("fixed content for testing")
            self.assertEqual(file_hash, string_hash)
        finally:
            tmp_file.unlink()

    def test_hash_file_missing_raises(self):
        with self.assertRaises(FileNotFoundError):
            hash_file("this_file_does_not_exist.txt")

    def test_verify_integrity_true_case(self):
        text = "secure message"
        h = hash_string(text)
        self.assertTrue(verify_integrity(text, h))

    def test_verify_integrity_false_case(self):
        text = "secure message"
        h = hash_string(text)
        self.assertFalse(verify_integrity("tampered message", h))


if __name__ == "__main__":
    unittest.main()
