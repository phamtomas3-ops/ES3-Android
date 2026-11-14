package dev.es3.core.format

import dev.es3.core.common.Es3Exception
import dev.es3.core.common.Es3Progress
import dev.es3.core.common.OriginalFileInfo
import dev.es3.core.crypto.Argon2idParams
import dev.es3.core.crypto.ChunkNonce
import dev.es3.core.crypto.Es3Aead
import dev.es3.core.crypto.Es3Kdf
import dev.es3.core.crypto.Es3Random
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

data class EncryptOptions(
    val chunkSize: Int = Es3Format.DEFAULT_CHUNK_SIZE,
    val kdf: Argon2idParams = Argon2idParams.DEFAULT
) {
    fun validate() {
        if (chunkSize < Es3Format.MIN_CHUNK_SIZE || chunkSize > Es3Format.MAX_CHUNK_SIZE)
            throw Es3Exception.InvalidParameters("chunk size out of range")
        kdf.validate()
    }
}

object Es3Encryptor {
    /**
     * Streams [input] (exactly [OriginalFileInfo.size] bytes) into an ES.3 container on [output].
     * Memory use is one chunk of plaintext + one chunk of ciphertext, independent of file size.
     * Not atomic: on failure [output] holds a partial container — use [encryptToFile] for safe file output.
     */
    fun encrypt(
        input: InputStream, info: OriginalFileInfo, password: CharArray, output: OutputStream,
        options: EncryptOptions = EncryptOptions(), progress: Es3Progress? = null
    ) {
        options.validate()
        try {
            val salt = Es3Random.bytes(Es3Format.SALT_LEN)
            val master = Es3Kdf.deriveMasterKey(password, salt, options.kdf)
            val (metaKey, payloadKey) = try {
                Pair(Es3Kdf.expand(master, Es3Format.INFO_METADATA_KEY), Es3Kdf.expand(master, Es3Format.INFO_PAYLOAD_KEY))
            } finally { master.fill(0) }
            val buf = ByteArray(options.chunkSize)
            try {
                val metaPlain = Es3Metadata.encode(info)
                val preMeta = Es3HeaderCodec.encodePreMeta(options.kdf, salt, options.chunkSize, metaPlain.size + Es3Format.TAG_LEN)
                // Metadata key is used for exactly one message (fresh per file), so a fixed zero nonce is safe.
                val metaCt = Es3Aead.seal(metaKey, ByteArray(Es3Format.NONCE_LEN), preMeta, metaPlain, 0, metaPlain.size)
                metaPlain.fill(0)
                val digest = java.security.MessageDigest.getInstance("SHA-256").digest(preMeta + metaCt)
                output.write(Es3HeaderCodec.finish(preMeta, metaCt))

                val size = info.size
                val count = Es3Chunking.chunkCount(size, options.chunkSize)
                var done = 0L
                var index = 0L
                while (index < count) {
                    val len = Es3Chunking.plainLength(index, count, size, options.chunkSize)
                    if (input.readUpTo(buf, 0, len) < len) throw Es3Exception.InvalidParameters("input is shorter than the declared size")
                    val aad = Es3Chunking.aad(digest, index, index == count - 1)
                    output.write(Es3Aead.seal(payloadKey, ChunkNonce.forIndex(index), aad, buf, 0, len))
                    done += len
                    progress?.onProgress(done, size)
                    index++
                }
                if (input.read() != -1) throw Es3Exception.InvalidParameters("input is longer than the declared size")
                output.flush()
            } finally {
                buf.fill(0); metaKey.fill(0); payloadKey.fill(0)
            }
        } catch (e: IOException) {
            throw ioToEs3(e)
        }
    }

    /**
     * Encrypts into a temporary file next to [destination], fsyncs it, then renames it into place
     * (atomic where the filesystem supports it). The original input is never modified; [destination]
     * is never overwritten unless [overwrite] is true. The temp file is deleted on any failure.
     */
    fun encryptToFile(
        input: InputStream, info: OriginalFileInfo, password: CharArray, destination: File,
        options: EncryptOptions = EncryptOptions(), progress: Es3Progress? = null, overwrite: Boolean = false
    ) {
        val dir = destination.absoluteFile.parentFile
        if (dir == null || !dir.isDirectory) throw Es3Exception.InvalidParameters("output directory does not exist")
        if (!overwrite && destination.exists()) throw Es3Exception.InvalidParameters("output file already exists")
        val tmp = try { File.createTempFile(".es3-enc-", ".tmp", dir) } catch (e: IOException) { throw ioToEs3(e) }
        var moved = false
        try {
            FileOutputStream(tmp).use { fos ->
                val out = BufferedOutputStream(fos, 64 * 1024)
                encrypt(input, info, password, out, options, progress)
                out.flush()
                fos.fd.sync()
            }
            moveIntoPlace(tmp, destination, overwrite)
            moved = true
        } catch (e: IOException) {
            throw ioToEs3(e)
        } finally {
            if (!moved) tmp.delete()
        }
    }
}
