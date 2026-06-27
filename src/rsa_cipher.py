"""
rsa_cipher.py
--------------
RSA asymmetric encryption: key generation, encryption/decryption, and
digital signatures.

WHY RSA:
RSA is an ASYMMETRIC cipher - it uses a *pair* of mathematically related
keys instead of one shared secret:
    public key  - safe to share with anyone, used to ENCRYPT or to VERIFY
                  a signature.
    private key - kept secret by the owner, used to DECRYPT or to CREATE
                  a signature.

RSA is much slower than AES and can only encrypt small amounts of data
(roughly key_size_in_bytes minus padding overhead), so in practice it's
used for:
    1. Encrypting a small AES key (then AES handles the actual bulk data -
       see hybrid_demo.py for this pattern).
    2. Digital signatures - proving a message came from the holder of a
       private key, and that it hasn't been altered.

PADDING SCHEMES USED:
    OAEP  - used for encryption (Crypto.Cipher.PKCS1_OAEP). Randomized
            padding that prevents a whole class of attacks plain "textbook
            RSA" is vulnerable to.
    PSS   - used for signatures (Crypto.Signature.pss). The modern,
            randomized signature padding scheme, preferred over the older
            deterministic PKCS#1 v1.5 signatures.

This module uses PyCryptodome's `Crypto.PublicKey.RSA`,
`Crypto.Cipher.PKCS1_OAEP`, and `Crypto.Signature.pss`.
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Hash import SHA256

DEFAULT_KEY_SIZE = 2048  # bits; 2048 is the current minimum recommended size


def generate_keypair(key_size: int = DEFAULT_KEY_SIZE):
    """
    Generate a new RSA key pair.

    Returns:
        A tuple (private_key, public_key) as RSA key objects. Use
        export_private_key() / export_public_key() to get PEM bytes
        suitable for saving to disk.
    """
    private_key = RSA.generate(key_size)
    public_key = private_key.publickey()
    return private_key, public_key


def export_private_key(private_key) -> bytes:
    """Export a private key as PEM-encoded bytes. Keep this SECRET."""
    return private_key.export_key()


def export_public_key(public_key) -> bytes:
    """Export a public key as PEM-encoded bytes. Safe to share."""
    return public_key.export_key()


def load_private_key(pem_bytes: bytes):
    """Load a private key from PEM-encoded bytes."""
    return RSA.import_key(pem_bytes)


def load_public_key(pem_bytes: bytes):
    """Load a public key from PEM-encoded bytes."""
    return RSA.import_key(pem_bytes)


def save_keypair_to_files(private_key, public_key, keys_dir: str = "keys"):
    """
    Save a key pair to <keys_dir>/private_key.pem and <keys_dir>/public_key.pem.

    NOTE: private_key.pem should never be committed to version control or
    shared - the .gitignore in this project already excludes the keys/
    directory for that reason.
    """
    from pathlib import Path

    keys_path = Path(keys_dir)
    keys_path.mkdir(exist_ok=True)

    (keys_path / "private_key.pem").write_bytes(export_private_key(private_key))
    (keys_path / "public_key.pem").write_bytes(export_public_key(public_key))


def encrypt(plaintext: bytes, public_key) -> bytes:
    """
    Encrypt data with RSA-OAEP using the recipient's public key.

    NOTE: RSA can only encrypt data smaller than the key size (roughly
    key_size_bytes - 66 bytes of OAEP overhead for SHA-256). For a 2048-bit
    key that's about 190 bytes max. For anything larger, use the hybrid
    approach in hybrid_demo.py instead.

    PyCryptodome's PKCS1_OAEP defaults to SHA-1 internally if no hash is
    given. SHA-1 is still fine for OAEP's purposes here, but this project
    pins SHA-256 explicitly to match the hash used elsewhere (signatures)
    and to follow current best practice.
    """
    cipher = PKCS1_OAEP.new(public_key, hashAlgo=SHA256)
    return cipher.encrypt(plaintext)


def decrypt(ciphertext: bytes, private_key) -> bytes:
    """Decrypt RSA-OAEP ciphertext using the matching private key."""
    cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
    return cipher.decrypt(ciphertext)


def sign(message: bytes, private_key) -> bytes:
    """
    Create a digital signature for a message using the private key.

    Internally this hashes the message with SHA-256 first, then signs the
    hash (not the raw message) using RSA-PSS padding.
    """
    h = SHA256.new(message)
    signature = pss.new(private_key).sign(h)
    return signature


def verify(message: bytes, signature: bytes, public_key) -> bool:
    """
    Verify a digital signature against a message using the public key.

    Returns:
        True if the signature is valid (message is authentic and
        untampered), False otherwise. Never raises for a bad signature -
        only for malformed input.
    """
    h = SHA256.new(message)
    try:
        pss.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
