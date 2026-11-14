# ES.3 cryptography (format v1)

## Primitives and libraries
| Purpose | Algorithm | Implementation |
|---|---|---|
| Password KDF | Argon2id v1.3 | Bouncy Castle `bcprov-jdk18on` 1.78.1, lightweight API (`Argon2BytesGenerator`); the BC JCE provider is not registered |
| Key separation | HKDF-Expand (RFC 5869), HMAC-SHA-256 | JCA `Mac` |
| AEAD | AES-256-GCM, 96-bit nonce, 128-bit tag | JCA `AES/GCM/NoPadding` (Conscrypt on Android) |
| Randomness | `java.security.SecureRandom` | platform |
| Header digest / checksum | SHA-256 / CRC-32 | JCA / `java.util.zip` |

## Key derivation
`master = Argon2id(password_utf8, salt[32], m, t, p, outlen=32)` — no secret, no associated data.
`metadata_key = HMAC-SHA256(master, "ES3/v1/metadata-key" ‖ 0x01)`
`payload_key  = HMAC-SHA256(master, "ES3/v1/payload-key"  ‖ 0x01)`

Password bytes are the UTF-8 encoding of the characters exactly as supplied (no normalization; unpaired surrogates and empty passwords are rejected). A future UI should normalize (e.g. NFC) *before* calling the engine if cross-device typing differences matter.

## Argon2id policy
Default for new files: **m = 64 MiB, t = 3, p = 1**. Accepted range on read *and* write: m 19 MiB–256 MiB, t 2–10, p 1–4. Out-of-range files are rejected, never silently adjusted. The parameters are stored in the header and bound by the metadata tag. Tests use the policy minimum (19 MiB, t = 2); production validation is not relaxed for tests.
Android note: the BC implementation is pure Java and single-threaded, and needs roughly `m` KiB of heap plus overhead. 64 MiB is expected to be fine but is **unmeasured** on the Infinix X6850; benchmark in Stage 7 and consider `android:largeHeap` if the app heap is tight.

## Nonce strategy and uniqueness argument
* Each file has a fresh random 256-bit salt → unique master key → unique `metadata_key` and `payload_key` (collision probability ≈ 2⁻²⁵⁶ per pair of files sharing a password).
* `metadata_key` encrypts exactly one message → fixed zero nonce is safe.
* `payload_key` encrypts one message per chunk; nonce = chunk index (u64 in a 96-bit field). Indices within a file are strictly increasing and never repeated, so no (key, nonce) pair repeats. Index 2⁶⁴ cannot be reached (file size is a signed 64-bit byte count).
* Separate keys for metadata and payload remove any cross-domain nonce reuse.
* Nonces are deterministic, so they are **not stored**; changing a chunk's position changes its nonce and AAD and fails authentication.

## Integrity of ordering and completeness
Every chunk's AAD contains the SHA-256 of the whole header, its index, and a final-chunk flag. Consequences: chunks cannot be reordered, duplicated, moved between files, or have the final flag moved; the last frame can only verify as final; frame lengths derive from the authenticated size, so a truncated file ends early (EOF) and an extended file has trailing bytes — both rejected. An empty file has one authenticated empty final chunk.

## Key lifecycle
Passwords arrive as `CharArray`; the UTF-8 copy, master key, subkeys, chunk buffers and decrypted chunk arrays are zeroed after use. Limits: `SecretKeySpec`/`Cipher` hold internal copies the JVM does not let us wipe, and callers (UI) must zero their own `CharArray`. Nothing is logged by the engine.
