package dev.es3.core.common

/**
 * Every failure of the ES.3 engine is one of these. Messages are user-safe: they never contain
 * passwords, keys, plaintext, salts, or file paths.
 */
sealed class Es3Exception(message: String, cause: Throwable? = null) : Exception(message, cause) {
    /** Header + metadata failed authentication. Cannot be told apart cryptographically from a tampered header. */
    class IncorrectPassword : Es3Exception("Incorrect password, or the file header was modified.")
    class InvalidFormat(detail: String) : Es3Exception("Not a valid ES.3 file: $detail")
    class UnsupportedVersion(val version: Int) : Es3Exception("Unsupported ES.3 format version: $version.")
    class UnsupportedFeature(detail: String) : Es3Exception("Unsupported ES.3 feature: $detail")
    /** A payload chunk failed its authentication tag. [chunkIndex] is the zero-based chunk. */
    class AuthenticationFailure(val chunkIndex: Long? = null) :
        Es3Exception("Authentication failed: the data is corrupted or has been modified.")
    class CorruptedHeader : Es3Exception("The file header is corrupted.")
    class CorruptedMetadata : Es3Exception("The file metadata is corrupted.")
    /** Chunks are missing, duplicated or out of order. */
    class ChunkSequence : Es3Exception("Encrypted chunks are missing, duplicated or out of order.")
    class TruncatedInput : Es3Exception("The file is incomplete (truncated).")
    class InsufficientStorage(cause: Throwable? = null) : Es3Exception("Not enough storage space.", cause)
    class IoFailure(cause: Throwable? = null) : Es3Exception("An I/O error occurred.", cause)
    class InvalidParameters(detail: String, cause: Throwable? = null) : Es3Exception("Invalid parameters: $detail", cause)
}
