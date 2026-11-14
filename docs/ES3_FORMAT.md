# ES.3 native container format — version 1

Native ES.3 format. **Not** the original EasySave3 format and not compatible with it. All integers are big-endian.

## Layout

| Offset | Size | Field | Notes |
|---|---|---|---|
| 0 | 8 | magic | `89 45 53 33 0D 0A 1A 0A` |
| 8 | 2 | format_version | `1`. Anything else → unsupported version |
| 10 | 2 | flags | must be `0` in v1 |
| 12 | 1 | kdf_id | `1` = Argon2id v1.3 |
| 13 | 1 | aead_id | `1` = AES-256-GCM, 128-bit tag |
| 14 | 4 | argon2_memory_kib | policy 19 456 … 262 144 |
| 18 | 4 | argon2_iterations | policy 2 … 10 |
| 22 | 1 | argon2_parallelism | policy 1 … 4 |
| 23 | 1 | salt_len | must be 32 |
| 24 | 32 | salt | random, per file |
| 56 | 4 | chunk_size | plaintext bytes per chunk, 4 096 … 67 108 864 |
| 60 | 4 | meta_len | metadata ciphertext length incl. tag, 29 … 1 024 |
| 64 | meta_len | metadata ciphertext | AES-256-GCM, see below |
| 64+meta_len | 4 | header_crc32 | CRC-32 (IEEE) of bytes `0 … 64+meta_len-1` |
| 68+meta_len | … | payload | chunk frames |

`preMeta` = bytes 0…63. `prefix` = preMeta ‖ metadata ciphertext. `header_digest` = SHA-256(prefix).

## Metadata (plaintext, before encryption)

`u8 compression_id (0 = none)` ‖ `u64 original_size` ‖ `u16 name_len` ‖ `name` (UTF-8, base name) ‖ `u8 ext_len` ‖ `ext` (UTF-8, no dot).

Limits: name ≤ 255 bytes, ext ≤ 32 bytes, full file name ≤ 255 bytes. No `/`, `\`, control characters; `.` and `..` forbidden. Readers must reject anything else. Parsing must consume exactly all bytes.
Sealed with the **metadata key**, nonce = 12 zero bytes (safe: that key encrypts exactly one message), AAD = `preMeta`.

## Payload

`chunk_count = max(1, ceil(original_size / chunk_size))`. Chunk *i* (0-based) holds `chunk_size` plaintext bytes, except the last, which holds the remainder (0 bytes only for an empty file). Each chunk is stored as `ciphertext ‖ 16-byte tag`, **with no length prefix** — every frame length is derived from the authenticated `original_size` and `chunk_size`.

* Key: payload key (see CRYPTOGRAPHY.md)
* Nonce (12 bytes): `00 00 00 00 ‖ u64 index`
* AAD (41 bytes): `header_digest (32) ‖ u64 index ‖ u8 final` (`1` for the last chunk, else `0`)

The file ends immediately after the last frame; trailing bytes make the file invalid.

## Reader algorithm (strict order)

1. Read magic; mismatch → invalid format. Read version; ≠ 1 → unsupported version.
2. Parse fixed fields; reject flags ≠ 0, unknown ids, out-of-policy KDF params, bad salt_len/chunk_size/meta_len **before allocating or deriving anything**.
3. Read metadata ciphertext and CRC; CRC mismatch → corrupted header (accidental-damage check only).
4. Derive keys; open metadata with AAD `preMeta`. Tag failure → "incorrect password or modified header". Validate metadata.
5. For each chunk: read exactly the expected frame length (EOF → truncated), open with the nonce/AAD above. Tag failure → authentication failure (or "chunks out of order" if the frame verifies as an adjacent index).
6. After the last chunk, require EOF.
7. Only now release the output (write to a temp file, fsync, rename).

## Versioning

Algorithm/KDF ids, flags and `compression_id` are reserved for future versions. A reader MUST reject unknown values rather than guess. Layout changes require a new `format_version`; v1 files stay readable forever. Compression (`compression_id ≠ 0`) is not implemented in v1 and is rejected.
