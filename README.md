# Cryptography Algorithms Implementation

An educational implementation of three core cryptography building blocks —
**AES** (symmetric encryption), **RSA** (asymmetric encryption + digital
signatures), and **SHA** (hashing) — built to understand how encryption,
decryption, and integrity verification actually work under the hood.

## Project Status

| Phase | Topic                          | Status     |
|-------|---------------------------------|------------|
| 1     | Project setup                   | ✅ Done    |
| 2     | SHA hashing                     | ✅ Done    |
| 3     | AES symmetric encryption        | ⬜ Pending |
| 4     | RSA asymmetric encryption       | ⬜ Pending |
| 5     | Hybrid RSA+AES demo             | ⬜ Pending |
| 6     | CLI integration                 | ⬜ Pending |
| 7     | Unit tests                      | 🟡 Started (SHA tests done) |
| 8     | OpenSSL cross-check              | ⬜ Pending |
| 9     | Docs + publish                  | ⬜ Pending |

## Project Structure

```
crypto-algorithms-project/
│
├── README.md
├── requirements.txt
├── .gitignore
│
├── src/
│   ├── __init__.py
│   ├── sha_hash.py        # SHA-256/384/512 hashing utilities (Phase 2 ✅)
│   ├── aes_cipher.py       # AES-GCM encryption (Phase 3)
│   ├── rsa_cipher.py       # RSA keygen, encryption, signatures (Phase 4)
│   └── utils.py            # shared helpers
│
├── cli/
│   └── main.py              # menu-driven demo app (Phase 6)
│
├── examples/
│   ├── sha_demo.py         # ✅ runnable demo
│   ├── aes_demo.py
│   ├── rsa_demo.py
│   └── hybrid_demo.py
│
├── tests/
│   ├── test_sha.py         # ✅ 9 passing tests
│   ├── test_aes.py
│   └── test_rsa.py
│
├── docs/
│   └── algorithm_notes.md  # write-up explaining how each algorithm works
│
└── keys/                    # generated RSA keys at runtime (gitignored)
```

## Setup

```bash
# 1. Clone the repo
git clone <your-repo-url>
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

**Run the SHA demo:**
```bash
python examples/sha_demo.py
```

**Run the test suite:**
```bash
python -m unittest discover tests
```

## Algorithms Implemented

### SHA (Secure Hash Algorithm) — ✅ Implemented
A one-way function that turns any input into a fixed-size fingerprint.
Used for integrity verification — you can't reverse a hash back into the
original data, but you can confirm data hasn't changed by comparing hashes.
Implemented in `src/sha_hash.py` using Python's built-in `hashlib`
(SHA-256, SHA-384, SHA-512).

### AES (Advanced Encryption Standard) — coming in Phase 3
A symmetric cipher — the same key encrypts and decrypts. Fast, used for
bulk data encryption (e.g. encrypting files, disk encryption, TLS session
data). Will use AES-GCM mode for authenticated encryption.

### RSA (Rivest–Shamir–Adleman) — coming in Phase 4
An asymmetric cipher — a public key encrypts, only the matching private key
can decrypt. Slower than AES, so it's typically used to encrypt small
things (like an AES key) or to create digital signatures, rather than bulk
data.

## License

This project is for educational purposes as part of an internship learning
exercise.
