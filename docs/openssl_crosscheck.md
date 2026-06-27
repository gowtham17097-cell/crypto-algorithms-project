# OpenSSL Cross-Check (Phase 8)

To make sure this project's implementations aren't just "internally
consistent" (passing only against themselves), each algorithm was
verified against the independent `openssl` command-line tool.

## SHA-256 — verified ✅

```bash
echo -n "OpenSSL cross-check message" | openssl dgst -sha256
```

Our `hash_string()` output and OpenSSL's digest matched byte-for-byte:
```
fcf7f2e24dc9dbd8e6dbad2f6937ec56fedb1ea72c9490926495d39abe853005
```

## RSA-OAEP encryption — verified ✅ (after a real fix)

Cross-checking this surfaced an actual bug-adjacent issue: PyCryptodome's
`PKCS1_OAEP.new(key)` defaults to **SHA-1** internally if no hash is
specified. The first cross-check attempt against `openssl pkeyutl` with
`-pkeyopt rsa_oaep_md:sha256` failed with an OAEP decoding error — not
because anything was broken, but because the two sides were using
different internal hash functions for the padding scheme.

Re-running the same OpenSSL command with `rsa_oaep_md:sha1` decrypted
correctly, confirming the *implementation* was correct all along — just
inconsistent with the SHA-256 used everywhere else in this project (e.g.
RSA-PSS signatures).

**Fix applied:** `src/rsa_cipher.py` now explicitly passes
`hashAlgo=SHA256` to `PKCS1_OAEP.new()` for both encryption and
decryption. SHA-1 was never a security problem here (it's only used
inside the padding scheme, not for the cipher itself), but pinning
SHA-256 explicitly makes behavior consistent and avoids relying on a
library default that could change.

After the fix, this now matches OpenSSL using `rsa_oaep_md:sha256`:
```bash
openssl pkeyutl -decrypt -inkey priv.pem \
  -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
  -in ciphertext.bin -out plaintext.txt
```

## RSA-PSS signatures — verified ✅

```bash
openssl dgst -sha256 -verify pub.pem \
  -sigopt rsa_padding_mode:pss \
  -signature signature.bin message.txt
# -> Verified OK
```

A signature produced by `src/rsa_cipher.sign()` verified successfully
against OpenSSL's independent PSS verification logic on the first try.

## AES-256-GCM — not cross-checked via CLI

The `openssl enc` subcommand's support for the GCM authentication tag
(`-tag`) is inconsistent across OpenSSL builds and distributions — some
builds don't expose it via `enc` at all, which is what this environment's
OpenSSL 3.0.13 build does. Rather than relying on an unsupported flag
across environments, AES-256-GCM correctness is instead covered by:
- `tests/test_aes.py` - round-trip, wrong-key, and tamper-detection tests
- Manual verification that the same key + nonce + ciphertext + tag
  combination always decrypts deterministically

A more thorough cross-check would use a small OpenSSL C program (via
`EVP_DecryptUpdate`/`EVP_CIPHER_CTX_ctrl` with `EVP_CTRL_GCM_SET_TAG`)
rather than the `enc` CLI subcommand, since the underlying library
support for GCM is solid - the CLI wrapper for it is just inconsistent.
