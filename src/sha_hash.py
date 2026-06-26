"""
sha_hash.py
------------
Utilities for cryptographic hashing using the SHA-2 family (SHA-256, SHA-384, SHA-512).

WHY HASHING MATTERS:
Hashing is a ONE-WAY function - given a hash digest, you cannot recover the
original input. This makes it useful for:
    - Integrity checks (e.g. verifying a downloaded file wasn't corrupted/tampered)
    - Storing password fingerprints (in real systems, always combined with a salt)
    - Digital signatures (you sign the HASH of a message, not the message itself)

A good hash function has two key properties demonstrated in examples/sha_demo.py:
    1. Deterministic  - same input always produces the same hash
    2. Avalanche effect - changing even one character of input completely
       changes the output hash

This module uses Python's built-in `hashlib`, so no external dependency
is required for hashing.
"""

import hashlib
from pathlib import Path

SUPPORTED_ALGORITHMS = {"sha256", "sha384", "sha512"}


def _get_hasher(algorithm: str):
    """Return a new hash object for the given algorithm, validating it first."""
    algorithm = algorithm.lower()
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. Choose from {sorted(SUPPORTED_ALGORITHMS)}."
        )
    return hashlib.new(algorithm)


def hash_string(text: str, algorithm: str = "sha256") -> str:
    """
    Compute the hash of a text string.

    Args:
        text: The input string to hash.
        algorithm: One of 'sha256', 'sha384', 'sha512'.

    Returns:
        Hexadecimal digest string.
    """
    hasher = _get_hasher(algorithm)
    hasher.update(text.encode("utf-8"))
    return hasher.hexdigest()


def hash_file(filepath: str, algorithm: str = "sha256", chunk_size: int = 65536) -> str:
    """
    Compute the hash of a file's contents, reading it in chunks so large
    files never need to be fully loaded into memory.

    Args:
        filepath: Path to the file.
        algorithm: One of 'sha256', 'sha384', 'sha512'.
        chunk_size: Bytes read per chunk (default 64KB).

    Returns:
        Hexadecimal digest string.
    """
    path = Path(filepath)
    if not path.is_file():
        raise FileNotFoundError(f"No such file: {filepath}")

    hasher = _get_hasher(algorithm)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def verify_integrity(
    text_or_filepath: str,
    expected_hash: str,
    algorithm: str = "sha256",
    is_file: bool = False,
) -> bool:
    """
    Check whether a string or file matches an expected hash.

    Args:
        text_or_filepath: The string to hash, or a path to a file (if is_file=True).
        expected_hash: The hash you're checking against (e.g. published by a
            download source).
        algorithm: Hash algorithm to use.
        is_file: Set True if text_or_filepath is a file path rather than raw text.

    Returns:
        True if the computed hash matches expected_hash (case-insensitive).
    """
    if is_file:
        actual = hash_file(text_or_filepath, algorithm)
    else:
        actual = hash_string(text_or_filepath, algorithm)
    return actual.lower() == expected_hash.strip().lower()
