# ES.3 security notes (Stage 2 engine)

## Threat model
**Protected:** confidentiality of file contents, original filename/extension/size (size is padded only to the chunk's tag; ciphertext length reveals approximate size and name length class), and integrity of everything, against an attacker who can read and modify the `.es3` file at rest and guess passwords offline (cost bounded by Argon2id).
**Not protected:** weak passwords; malware/root on the device while the app runs; screenshots/clipboard; plaintext after decryption; side channels in the JVM/OS; the existence, approximate size and chunk size of the file.

## Behaviours guaranteed by design (and covered by tests)
* No plaintext is exposed unless every chunk tag and the end-of-input check pass: decryption writes to a private temp file and renames only after full verification; there is no "decrypt to arbitrary stream" API.
* Failed encrypt/decrypt deletes its temp file; input files are never modified; existing outputs are never overwritten by default (decrypt picks `name (1).ext`).
* Untrusted lengths are range-checked before use; all size arithmetic is `Long`; frame lengths are derived, not read.
* Output file names come from authenticated metadata and are additionally validated and path-checked.
* Header edits are caught by CRC (accidental) or by the metadata tag (deliberate).

## Known limitations / residual concerns
1. **Wrong password vs. tampered header are indistinguishable** once the CRC passes; both report `IncorrectPassword`.
2. Plaintext of *already-verified* chunks sits in a `0600` temp file in the output directory until the whole file verifies. It is deleted on failure but not securely wiped (flash storage, journaling).
3. Rename-based finalization has a small check-then-rename race on the non-overwrite path; single-user app assumed.
4. SAF/`content://` destinations are not supported by this layer; the Android layer must stage via a local temp file (a later stage).
5. Argon2id runs in pure Java; timings on target hardware are unmeasured.
6. Chunk size and Argon2 parameters are visible in the clear.
7. No decompression exists yet (Stage 4); decompression-bomb limits must be designed then.
8. The Argon2id known-answer test (RFC 9106 vector) exercises the library, not our wrapper, and was entered from memory of the RFC — if it fails, check the vector first.
9. Not independently audited. Do not use as the sole protection for high-value secrets.
