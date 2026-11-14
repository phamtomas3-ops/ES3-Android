package dev.es3.core.format

import java.nio.ByteBuffer

internal object Es3Chunking {
    /** An empty file still has exactly one (empty, final) chunk so that finalization is always authenticated. */
    fun chunkCount(size: Long, chunkSize: Int): Long =
        if (size == 0L) 1L else size / chunkSize + (if (size % chunkSize != 0L) 1L else 0L)

    fun plainLength(index: Long, count: Long, size: Long, chunkSize: Int): Int =
        if (index < count - 1) chunkSize else (size - (count - 1) * chunkSize).toInt()

    /** AAD = SHA-256(header) (32) || chunk index u64 BE (8) || final flag u8 (1). */
    fun aad(headerDigest: ByteArray, index: Long, isFinal: Boolean): ByteArray =
        ByteBuffer.allocate(headerDigest.size + 9).put(headerDigest).putLong(index)
            .put((if (isFinal) 1 else 0).toByte()).array()
}
