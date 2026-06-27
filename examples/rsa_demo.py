"""
rsa_demo.py
------------
Run this file directly to see RSA encryption and digital signatures in
action.

Usage:
    python examples/rsa_demo.py
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.rsa_cipher import generate_keypair, encrypt, decrypt, sign, verify
from src.utils import bytes_to_b64, print_section


def demo_keypair_generation():
    print_section("1. RSA KEY PAIR GENERATION")
    print("Generating a 2048-bit RSA key pair (this can take a moment)...")
    private_key, public_key = generate_keypair()
    print(f"Public key size:  {public_key.size_in_bits()} bits")
    print(f"Private key size: {private_key.size_in_bits()} bits")
    print()
    return private_key, public_key


def demo_encryption(private_key, public_key):
    print_section("2. RSA ENCRYPTION (public key encrypts, private key decrypts)")
    message = b"Meet at the usual place, 9pm."

    ciphertext = encrypt(message, public_key)
    print(f"Original message: {message.decode()}")
    print(f"Ciphertext (b64):  {bytes_to_b64(ciphertext)[:60]}...")

    decrypted = decrypt(ciphertext, private_key)
    print(f"Decrypted message: {decrypted.decode()}")
    print(f"Match original?    {decrypted == message}")
    print()


def demo_digital_signature(private_key, public_key):
    print_section("3. DIGITAL SIGNATURES (private key signs, public key verifies)")
    message = b"This contract is agreed to by both parties."

    signature = sign(message, private_key)
    print(f"Message:           {message.decode()}")
    print(f"Signature (b64):   {bytes_to_b64(signature)[:60]}...")

    is_valid = verify(message, signature, public_key)
    print(f"Signature valid?   {is_valid}")

    # Now simulate someone tampering with the message after it was signed
    tampered_message = b"This contract is agreed to by ONE party only."
    is_valid_tampered = verify(tampered_message, signature, public_key)
    print(f"Signature valid for tampered message? {is_valid_tampered}")
    print()


if __name__ == "__main__":
    priv, pub = demo_keypair_generation()
    demo_encryption(priv, pub)
    demo_digital_signature(priv, pub)
