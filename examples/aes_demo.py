"""
aes_demo.py
------------
Run this file directly to see AES-GCM symmetric encryption in action,
including what happens when ciphertext is tampered with.

Usage:
    python examples/aes_demo.py
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.aes_cipher import generate_key, encrypt, decrypt, encrypt_string, decrypt_to_string
from src.utils import bytes_to_b64, print_section


def demo_basic_encryption():
    print_section("1. BASIC AES-256-GCM ENCRYPTION")
    key = generate_key()
    message = "The launch code is 4471-Bravo."

    result = encrypt_string(message, key)
    print(f"Original message: {message}")
    print(f"Key (base64):      {bytes_to_b64(key)}")
    print(f"Nonce (base64):    {bytes_to_b64(result['nonce'])}")
    print(f"Ciphertext (b64):  {bytes_to_b64(result['ciphertext'])}")
    print(f"Auth tag (b64):    {bytes_to_b64(result['tag'])}")

    decrypted = decrypt_to_string(result["nonce"], result["ciphertext"], result["tag"], key)
    print(f"Decrypted message: {decrypted}")
    print(f"Match original?    {decrypted == message}")
    print()


def demo_wrong_key_fails():
    print_section("2. DECRYPTION WITH THE WRONG KEY")
    key_a = generate_key()
    key_b = generate_key()  # an attacker's (or simply incorrect) key

    result = encrypt_string("Top secret payload", key_a)

    try:
        decrypt_to_string(result["nonce"], result["ciphertext"], result["tag"], key_b)
        print("Unexpectedly succeeded - this should not happen!")
    except ValueError as e:
        print(f"Decryption with wrong key failed as expected: {e}")
    print()


def demo_tamper_detection():
    print_section("3. TAMPER DETECTION (the 'A' in AES-GCM = Authenticated)")
    key = generate_key()
    result = encrypt_string("Transfer $100 to Alice", key)

    print("Original ciphertext encrypted successfully.")

    # Flip a single bit in the ciphertext to simulate tampering
    tampered = bytearray(result["ciphertext"])
    tampered[0] ^= 0x01  # flip the lowest bit of the first byte
    tampered_ciphertext = bytes(tampered)

    print("Simulating an attacker flipping a single bit in the ciphertext...")
    try:
        decrypt(result["nonce"], tampered_ciphertext, result["tag"], key)
        print("Unexpectedly succeeded - this should not happen!")
    except ValueError as e:
        print(f"Tampering detected, decryption refused: {e}")
        print("This is exactly the protection GCM mode adds over plain AES.")
    print()


if __name__ == "__main__":
    demo_basic_encryption()
    demo_wrong_key_fails()
    demo_tamper_detection()
