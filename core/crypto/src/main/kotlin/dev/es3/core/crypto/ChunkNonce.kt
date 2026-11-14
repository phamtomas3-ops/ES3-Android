package dev.es3.core.crypto

import java.nio.ByteBuffer

/**
 * 96-bit AES-GCM nonce for payload chunk `index`: 4 zero bytes || index as 64-bit big-endian.
 * Uniqueness: every file has its own payload key (random 256-bit salt -> Argon2id -> HKDF), and within
 * one file each chunk index is used exactly once, so (key, nonce) pairs never repeat.
 */
object ChunkNonce {
    fun forIndex(index: Long): ByteArray {
        require(index >= 0) { "chunk index must not be negative" }
        return ByteBuffer.allocate(Es3Aead.NONCE_LEN).putInt(0).putLong(index).array()
    }
}
