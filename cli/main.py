"""
main.py
--------
Menu-driven CLI demo app tying together SHA, AES, RSA, and hybrid
encryption from one place.

Usage:
    python cli/main.py
"""

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from src.sha_hash import hash_string
from src.aes_cipher import generate_key as aes_generate_key, encrypt_string, decrypt_to_string
from src.rsa_cipher import generate_keypair, sign, verify
from src.utils import bytes_to_b64

# In-memory session state so keys persist between menu choices without
# writing to disk (keys/ is only used if the user explicitly saves).
_session = {
    "aes_key": None,
    "rsa_private": None,
    "rsa_public": None,
}


def menu_hash():
    text = input("Enter text to hash: ")
    algo = input("Algorithm [sha256/sha384/sha512] (default sha256): ").strip() or "sha256"
    try:
        digest = hash_string(text, algo)
        print(f"\n{algo.upper()} digest:\n{digest}\n")
    except ValueError as e:
        print(f"Error: {e}\n")


def menu_aes_setup():
    _session["aes_key"] = aes_generate_key()
    print(f"\nNew AES-256 key generated (session only): {bytes_to_b64(_session['aes_key'])}\n")


def menu_aes_encrypt():
    if _session["aes_key"] is None:
        print("\nNo AES key yet - generating one for this session.")
        menu_aes_setup()
    text = input("Enter text to encrypt: ")
    result = encrypt_string(text, _session["aes_key"])
    print("\nEncrypted (save all three to decrypt later):")
    print(f"  nonce:      {bytes_to_b64(result['nonce'])}")
    print(f"  ciphertext: {bytes_to_b64(result['ciphertext'])}")
    print(f"  tag:        {bytes_to_b64(result['tag'])}\n")
    _session["last_aes_result"] = result


def menu_aes_decrypt():
    if _session["aes_key"] is None or "last_aes_result" not in _session:
        print("\nNothing to decrypt yet - encrypt something first in this session.\n")
        return
    result = _session["last_aes_result"]
    decrypted = decrypt_to_string(result["nonce"], result["ciphertext"], result["tag"], _session["aes_key"])
    print(f"\nDecrypted text: {decrypted}\n")


def menu_rsa_setup():
    print("\nGenerating 2048-bit RSA key pair (may take a moment)...")
    _session["rsa_private"], _session["rsa_public"] = generate_keypair()
    print("RSA key pair generated for this session.\n")


def menu_rsa_sign():
    if _session["rsa_private"] is None:
        print("\nNo RSA keys yet - generating them for this session.")
        menu_rsa_setup()
    text = input("Enter message to sign: ")
    signature = sign(text.encode("utf-8"), _session["rsa_private"])
    _session["last_signed_message"] = text
    _session["last_signature"] = signature
    print(f"\nSignature (b64): {bytes_to_b64(signature)}\n")


def menu_rsa_verify():
    if "last_signature" not in _session:
        print("\nNothing signed yet in this session - sign a message first.\n")
        return
    text = input(
        f"Enter message to verify (press Enter to reuse the original message): "
    ).strip() or _session["last_signed_message"]
    is_valid = verify(text.encode("utf-8"), _session["last_signature"], _session["rsa_public"])
    print(f"\nSignature valid? {is_valid}\n")


MENU_OPTIONS = {
    "1": ("SHA: hash a string", menu_hash),
    "2": ("AES: generate a new session key", menu_aes_setup),
    "3": ("AES: encrypt a string", menu_aes_encrypt),
    "4": ("AES: decrypt the last result", menu_aes_decrypt),
    "5": ("RSA: generate a new session key pair", menu_rsa_setup),
    "6": ("RSA: sign a message", menu_rsa_sign),
    "7": ("RSA: verify the last signature", menu_rsa_verify),
}


def print_menu():
    print("=" * 60)
    print("Cryptography Algorithms Demo - Main Menu")
    print("=" * 60)
    for key, (label, _) in MENU_OPTIONS.items():
        print(f"  {key}. {label}")
    print("  0. Exit")
    print("=" * 60)


def main():
    while True:
        print_menu()
        choice = input("Choose an option: ").strip()
        if choice == "0":
            print("Goodbye!")
            break
        option = MENU_OPTIONS.get(choice)
        if option is None:
            print("\nInvalid option, try again.\n")
            continue
        _, handler = option
        try:
            handler()
        except Exception as e:  # keep the menu loop alive on bad input
            print(f"\nSomething went wrong: {e}\n")


if __name__ == "__main__":
    main()
