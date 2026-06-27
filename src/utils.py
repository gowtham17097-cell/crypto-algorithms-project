"""
utils.py
---------
Small shared helper functions used across the AES, RSA, and hybrid demos.
"""

import base64


def bytes_to_b64(data: bytes) -> str:
    """Encode raw bytes as a base64 string, for printing/storing/transmitting."""
    return base64.b64encode(data).decode("ascii")


def b64_to_bytes(b64_string: str) -> bytes:
    """Decode a base64 string back into raw bytes."""
    return base64.b64decode(b64_string)


def print_section(title: str, width: int = 60):
    """Print a consistent section header, used by the example demo scripts."""
    print("=" * width)
    print(title)
    print("=" * width)
