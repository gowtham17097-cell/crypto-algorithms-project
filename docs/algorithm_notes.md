# Algorithm Notes

A plain-language write-up of how each algorithm in this project actually
works, why it's designed the way it is, and where it's used in the real
world.

## SHA (Secure Hash Algorithm)

**Type:** One-way hash function (no key involved).

**What it does:** Takes input of *any* size and produces a fixed-size
"fingerprint" (256 bits for SHA-256, 512 bits for SHA-512). The same input
always produces the same output, but there's no way to reverse the output
back into the input.

**Two properties that make it useful:**
- **Deterministic** - hash it twice, get the same answer twice. This is
  what lets you verify a downloaded file matches a published checksum.
- **Avalanche effect** - changing a single bit of input changes roughly
  half the output bits, unpredictably. This is what makes hashes useless
  for an attacker trying to find a "close enough" input that produces the
  hash they want.

**Real-world uses:** file integrity checks, Git commit hashes, password
storage (hashed + salted, never stored in plaintext), the basis of digital
signatures (you sign the *hash* of a document, not the document itself).

**Implemented in:** `src/sha_hash.py`, using Python's built-in `hashlib`.

---

## AES (Advanced Encryption Standard)

**Type:** Symmetric cipher (one shared secret key encrypts AND decrypts).

**What it does:** Scrambles data into ciphertext that's unreadable without
the key, and turns it back into the original data given the same key.

**Why GCM mode specifically:** Plain AES only provides confidentiality —
it hides data, but doesn't stop someone from *tampering* with the
ciphertext. GCM mode bundles in an authentication tag, so any tampering
(even a single flipped bit) is detected and decryption is refused rather
than silently returning corrupted data. This combination is called
**authenticated encryption**.

**Key concepts:**
- **Key** - the 256-bit secret. Whoever has it can both encrypt and
  decrypt, so it must be kept private and shared securely.
- **Nonce** - a 96-bit value that must be unique for every encryption
  with the same key. Reusing a nonce with GCM is a serious security flaw
  (it can leak the key), which is why a fresh random nonce is generated
  on every call in this project.
- **Tag** - the authentication tag produced alongside the ciphertext;
  required to decrypt, and decryption fails loudly if it doesn't match.

**Real-world uses:** disk encryption (BitLocker, FileVault), VPNs, the
bulk-data phase of TLS/HTTPS connections, encrypted messaging payloads.

**Implemented in:** `src/aes_cipher.py`, using PyCryptodome's
`Crypto.Cipher.AES` in `MODE_GCM`.

---

## RSA (Rivest–Shamir–Adleman)

**Type:** Asymmetric cipher (a *pair* of mathematically linked keys).

**What it does:** Anything encrypted with the public key can only be
decrypted with the matching private key. Separately, anything signed with
the private key can be verified by anyone holding the public key.

**Why asymmetric matters:** With AES, both parties need the *same* secret
key — but how do you get that key to the other person in the first place
without an eavesdropper intercepting it? RSA solves that "key
distribution problem": you can publish your public key openly, and
anyone can use it to send you something only you can read.

**Trade-off:** RSA is much slower than AES and can only encrypt data
smaller than its key size (roughly 214 bytes for a 2048-bit key with OAEP
padding). It's not meant for bulk data — see the hybrid pattern below.

**Padding schemes used in this project:**
- **OAEP** (for encryption) — randomized padding that defeats a range of
  mathematical attacks that "textbook" (unpadded) RSA is vulnerable to.
- **PSS** (for signatures) — the modern, randomized signature padding
  scheme, preferred over the older deterministic PKCS#1 v1.5 scheme.

**Real-world uses:** TLS/HTTPS handshakes, SSH key authentication, code
signing, PGP/GPG email encryption.

**Implemented in:** `src/rsa_cipher.py`, using PyCryptodome's
`Crypto.PublicKey.RSA`, `Crypto.Cipher.PKCS1_OAEP`, and
`Crypto.Signature.pss`.

---

## Hybrid Encryption (RSA + AES together)

**The problem:** AES is fast but needs a shared key. RSA solves the
key-sharing problem but is too slow and size-limited for real data.

**The solution every real system actually uses:**
1. Generate a random AES key (a "session key") for this one message.
2. Encrypt the actual data with AES — fast, no size limit.
3. Encrypt *just the small AES key* with the recipient's RSA public key.
4. Send both pieces together: the RSA-wrapped AES key, plus the AES
   ciphertext.
5. The recipient uses their RSA private key to unwrap the AES key, then
   uses that AES key to decrypt the actual data.

This is conceptually exactly what happens in a TLS/HTTPS handshake: an
asymmetric exchange establishes a symmetric session key, and the
symmetric cipher does the heavy lifting for the rest of the connection.

**Implemented in:** `examples/hybrid_demo.py`, combining
`src/aes_cipher.py` and `src/rsa_cipher.py`.
