# Cryptography Algorithms Implementation

[![Tests](https://github.com/gowtham17097-cell/crypto-algorithms-project/actions/workflows/tests.yml/badge.svg)](https://github.com/gowtham17097-cell/crypto-algorithms-project/actions/workflows/tests.yml)

An educational implementation of three core cryptography building blocks —
**AES** (symmetric encryption), **RSA** (asymmetric encryption + digital
signatures), and **SHA** (hashing) — built to understand how encryption,
decryption, and integrity verification actually work under the hood.

## Project Status

| Phase | Topic                      | Status  |
|-------|----------------------------|---------|
| 1     | Project setup              | ✅ Done |
| 2     | SHA hashing                | ✅ Done |
| 3     | AES symmetric encryption   | ✅ Done |
| 4     | RSA asymmetric encryption  | ✅ Done |
| 5     | Hybrid RSA+AES demo        | ✅ Done |
| 6     | CLI integration            | ✅ Done |
| 7     | Unit tests                 | ✅ Done (30 passing) |
| 8     | OpenSSL cross-check        | ✅ Done ([details](docs/openssl_crosscheck.md)) |
| 9     | Docs + publish             | ✅ Done |

## Project Structure

```
crypto-algorithms-project/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── .github/
│   └── workflows/
│       └── tests.yml        # CI: runs the full test suite on every push
│
├── src/
│   ├── __init__.py
│   ├── sha_hash.py          # SHA-256/384/512 hashing utilities
│   ├── aes_cipher.py        # AES-256-GCM authenticated encryption
│   ├── rsa_cipher.py        # RSA-2048 keygen, OAEP encryption, PSS signatures
│   └── utils.py             # shared helpers (base64 encoding, etc.)
│
├── cli/
│   └── main.py               # menu-driven demo app tying everything together
│
├── examples/
│   ├── sha_demo.py
│   ├── aes_demo.py
│   ├── rsa_demo.py
│   └── hybrid_demo.py        # RSA + AES combined, the pattern TLS actually uses
│
├── tests/
│   ├── test_sha.py           # 9 tests
│   ├── test_aes.py           # 10 tests
│   └── test_rsa.py           # 11 tests
│
├── docs/
│   ├── algorithm_notes.md         # how each algorithm works, in plain language
│   └── openssl_crosscheck.md      # verification against the openssl CLI
│
└── keys/                      # generated RSA keys at runtime (gitignored)
```

## Setup

```bash
# 1. Clone the repo
git clone https://github.com/gowtham17097-cell/crypto-algorithms-project.git
cd crypto-algorithms-project

# 2. Create a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
```

> **Note:** `requirements.txt` uses **PyCryptodome**, not the original
> PyCrypto library. PyCrypto is unmaintained and has known security
> vulnerabilities — PyCryptodome is its actively-maintained, drop-in
> replacement and is what's actually meant in most modern references to
> "PyCrypto."

## Usage

**Run the interactive CLI** (the easiest way to try everything):
```bash
python cli/main.py
```

**Run individual demos:**
```bash
python examples/sha_demo.py
python examples/aes_demo.py
python examples/rsa_demo.py
python examples/hybrid_demo.py
```

**Run the full test suite:**
```bash
python -m unittest discover tests -v
```

Tests also run automatically on every push via GitHub Actions — see the
badge at the top of this README, or the **Actions** tab on GitHub.

## Algorithms Implemented

### SHA (Secure Hash Algorithm)
A one-way function that turns any input into a fixed-size fingerprint.
Used for integrity verification — you can't reverse a hash back into the
original data, but you can confirm data hasn't changed by comparing hashes.
Implemented in `src/sha_hash.py` using Python's built-in `hashlib`
(SHA-256, SHA-384, SHA-512). Cross-checked against `openssl dgst`.

### AES (Advanced Encryption Standard)
A symmetric cipher — the same 256-bit key encrypts and decrypts. Fast,
used for bulk data encryption (disk encryption, TLS session data).
Implemented in `src/aes_cipher.py` using AES-256-GCM, which adds an
authentication tag so any tampering with the ciphertext is detected
rather than silently producing corrupted output.

### RSA (Rivest–Shamir–Adleman)
An asymmetric cipher — a public key encrypts (or verifies signatures),
only the matching private key can decrypt (or create signatures).
Implemented in `src/rsa_cipher.py` with 2048-bit keys, OAEP padding for
encryption, and PSS padding for signatures — both cross-checked against
the `openssl` CLI (see `docs/openssl_crosscheck.md`, which also covers a
real SHA-1-vs-SHA-256 inconsistency the cross-check caught and fixed).

### Hybrid RSA + AES
RSA is slow and size-limited; AES needs a securely shared key. The
standard real-world fix — used by TLS/HTTPS itself — is to generate a
random AES key per message, encrypt the actual data with AES, and encrypt
*only that small AES key* with RSA. Implemented in `examples/hybrid_demo.py`.

## License

This project is for educational purposes as part of an internship learning
exercise.
