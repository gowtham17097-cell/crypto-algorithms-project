"""
hybrid_demo.py
---------------
Run this file directly to see the HYBRID encryption pattern that real-world
systems (TLS, PGP, encrypted messaging apps, etc.) actually use.

WHY HYBRID?
RSA is secure but slow and can only encrypt small amounts of data.
AES is fast and can encrypt data of any size, but needs the key shared
somehow.

The hybrid approach gets the best of both:
    1. Generate a random AES key (the "session key").
    2. Encrypt the actual (potentially large) message with AES - fast.
    3. Encrypt the small AES key itself with the recipient's RSA public
       key - this solves the "how do I get the key to them safely"
       problem, since only their RSA private key can recover it.
    4. Send: (RSA-encrypted AES key) + (AES nonce, ciphertext, tag).
    5. Recipient decrypts the AES key with their RSA private key, then
       uses that AES key to decrypt the actual message.

This is exactly what happens, conceptually, in TLS/HTTPS: an asymmetric
handshake establishes a symmetric session key, then the symmetric key
does the heavy lifting for the rest of the connection.

Usage:
    python examples/hybrid_demo.py
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.aes_cipher import generate_key, encrypt as aes_encrypt, decrypt as aes_decrypt
from src.rsa_cipher import generate_keypair, encrypt as rsa_encrypt, decrypt as rsa_decrypt
from src.utils import bytes_to_b64, print_section


def hybrid_encrypt(plaintext: bytes, rsa_public_key) -> dict:
    """
    Encrypt plaintext of any size using the hybrid RSA+AES pattern.

    Returns a dict containing everything the recipient needs:
        encrypted_aes_key - the AES session key, RSA-encrypted
        nonce, ciphertext, tag - the AES-GCM encrypted payload
    """
    aes_key = generate_key()
    aes_result = aes_encrypt(plaintext, aes_key)
    encrypted_aes_key = rsa_encrypt(aes_key, rsa_public_key)

    return {
        "encrypted_aes_key": encrypted_aes_key,
        "nonce": aes_result["nonce"],
        "ciphertext": aes_result["ciphertext"],
        "tag": aes_result["tag"],
    }


def hybrid_decrypt(package: dict, rsa_private_key) -> bytes:
    """Reverse of hybrid_encrypt(): recover the AES key, then the plaintext."""
    aes_key = rsa_decrypt(package["encrypted_aes_key"], rsa_private_key)
    plaintext = aes_decrypt(package["nonce"], package["ciphertext"], package["tag"], aes_key)
    return plaintext


def demo_hybrid_roundtrip():
    print_section("HYBRID RSA + AES ENCRYPTION")

    print("Generating recipient's RSA key pair...")
    private_key, public_key = generate_keypair()

    # A message larger than RSA could encrypt directly (RSA-2048/OAEP tops
    # out around 214 bytes) - this is the whole point of going hybrid.
    message = (
        b"This is a much longer message than RSA alone could encrypt "
        b"directly. " * 5
    )
    print(f"Message length: {len(message)} bytes (too large for direct RSA-2048 encryption)")
    print()

    print("Sender: encrypting with hybrid RSA+AES...")
    package = hybrid_encrypt(message, public_key)
    print(f"  RSA-encrypted AES key (b64): {bytes_to_b64(package['encrypted_aes_key'])[:60]}...")
    print(f"  AES ciphertext (b64):        {bytes_to_b64(package['ciphertext'])[:60]}...")
    print()

    print("Recipient: decrypting with their RSA private key + recovered AES key...")
    recovered = hybrid_decrypt(package, private_key)
    print(f"  Decrypted message matches original? {recovered == message}")
    print()


if __name__ == "__main__":
    demo_hybrid_roundtrip()
