"""
sha_demo.py
------------
Run this file directly to see SHA hashing in action, including the
'avalanche effect' - where a tiny change to the input causes a completely
different hash output.

Usage:
    python examples/sha_demo.py
"""

import sys
from pathlib import Path

# Allow running this script directly without installing the package
sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.sha_hash import hash_string, hash_file, verify_integrity


def demo_basic_hashing():
    print("=" * 60)
    print("1. BASIC HASHING")
    print("=" * 60)
    message = "Hello, Cryptography!"
    for algo in ("sha256", "sha384", "sha512"):
        digest = hash_string(message, algo)
        print(f"{algo.upper():8} -> {digest}")
    print()


def demo_avalanche_effect():
    print("=" * 60)
    print("2. AVALANCHE EFFECT (one character changes everything)")
    print("=" * 60)
    msg_a = "I owe you $100"
    msg_b = "I owe you $900"  # only one digit different

    hash_a = hash_string(msg_a)
    hash_b = hash_string(msg_b)

    print(f"Message A: {msg_a}")
    print(f"SHA-256 A: {hash_a}")
    print()
    print(f"Message B: {msg_b}")
    print(f"SHA-256 B: {hash_b}")
    print()
    print("Notice the two hashes share almost nothing in common,")
    print("even though only a single digit changed in the input.")
    print()


def demo_file_integrity():
    print("=" * 60)
    print("3. FILE INTEGRITY CHECK")
    print("=" * 60)

    sample_path = Path(__file__).resolve().parent / "sample_file.txt"
    sample_path.write_text("This is the original, untouched file content.\n")

    original_hash = hash_file(str(sample_path))
    print(f"Original file hash: {original_hash}")

    is_valid = verify_integrity(str(sample_path), original_hash, is_file=True)
    print(f"Integrity check (unmodified file): {'PASSED' if is_valid else 'FAILED'}")

    # Simulate tampering by changing the file content slightly
    sample_path.write_text("This is the original, untouched file content!\n")
    is_valid_after_tamper = verify_integrity(str(sample_path), original_hash, is_file=True)
    print(f"Integrity check (after tampering):  {'PASSED' if is_valid_after_tamper else 'FAILED'}")

    sample_path.unlink()  # clean up the temp file
    print()


if __name__ == "__main__":
    demo_basic_hashing()
    demo_avalanche_effect()
    demo_file_integrity()
