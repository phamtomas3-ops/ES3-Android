package dev.es3.core.format

import dev.es3.core.common.Es3Exception
import dev.es3.core.common.Es3Progress
import dev.es3.core.common.OriginalFileInfo
import dev.es3.core.crypto.ChunkNonce
import dev.es3.core.crypto.Es3Aead
import dev.es3.core.crypto.Es3Kdf
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

data class DecryptResult(val file: File, val info: OriginalFileInfo)

/**
 * Decryption deliberately has NO "write plaintext to an arbitrary stream" entry point: plaintext is
 * written to a private temp file, and only after the final chunk and end-of-input have verified is the
 * file renamed to its final name. A failed decryption leaves no output file.
 */
object Es3Decryptor {
    private class Opened(val header: Es3Header, val info: OriginalFileInfo, val payloadKey: ByteArray)

    /**
     * Authenticates header + metadata only (cost: one Argon2id run). This does NOT prove the payload is intact;
     * use [decryptToFile] for that.
     */
    fun readMetadata(input: InputStream, password: CharArray): OriginalFileInfo {
        val opened = try { open(input, password) } catch (e: IOException) { throw ioToEs3(e) }
        opened.payloadKey.fill(0)
        return opened.info
    }

    fun decryptToFile(input: InputStream, password: CharArray, outputDir: File, progress: Es3Progress? = null): DecryptResult {
        val dir = outputDir.absoluteFile
        if (!dir.isDirectory) throw Es3Exception.InvalidParameters("output directory does not exist")
        val opened = try { open(input, password) } catch (e: IOException) { throw ioToEs3(e) }
        try {
            val tmp = try { File.createTempFile(".es3-dec-", ".tmp", dir) } catch (e: IOException) { throw ioToEs3(e) }
            var moved = false
            try {
                FileOutputStream(tmp).use { fos ->
                    val out = BufferedOutputStream(fos, 64 * 1024)
                    verifyAndWrite(input, opened, out, progress)
                    out.flush()
                    fos.fd.sync()
                }
                val target = uniqueTarget(dir, opened.info)
                moveIntoPlace(tmp, target, replace = false)
                moved = true
                return DecryptResult(target, opened.info)
            } catch (e: IOException) {
                throw ioToEs3(e)
            } finally {
                if (!moved) tmp.delete()
            }
        } finally {
            opened.payloadKey.fill(0)
        }
    }

    private fun open(input: InputStream, password: CharArray): Opened {
        val header = Es3HeaderCodec.read(input)
        val master = Es3Kdf.deriveMasterKey(password, header.salt, header.kdf)
        val (metaKey, payloadKey) = try {
            Pair(Es3Kdf.expand(master, Es3Format.INFO_METADATA_KEY), Es3Kdf.expand(master, Es3Format.INFO_PAYLOAD_KEY))
        } finally { master.fill(0) }
        var success = false
        try {
            val plain = try {
                Es3Aead.open(metaKey, ByteArray(Es3Format.NONCE_LEN), header.preMeta, header.metaCiphertext, 0, header.metaCiphertext.size)
            } catch (e: Es3Exception.AuthenticationFailure) {
                throw Es3Exception.IncorrectPassword()
            }
            val info = try { Es3Metadata.decode(plain) } finally { plain.fill(0) }
            success = true
            return Opened(header, info, payloadKey)
        } finally {
            metaKey.fill(0)
            if (!success) payloadKey.fill(0)
        }
    }

    private fun verifyAndWrite(input: InputStream, opened: Opened, out: OutputStream, progress: Es3Progress?) {
        val chunkSize = opened.header.chunkSize
        val size = opened.info.size
        val count = Es3Chunking.chunkCount(size, chunkSize)
        val digest = opened.header.digest()
        val buf = ByteArray(chunkSize + Es3Format.TAG_LEN)
        try {
            var done = 0L
            var index = 0L
            while (index < count) {
                val plainLen = Es3Chunking.plainLength(index, count, size, chunkSize)
                val frameLen = plainLen + Es3Format.TAG_LEN
                if (input.readUpTo(buf, 0, frameLen) < frameLen) throw Es3Exception.TruncatedInput()
                val plain = try {
                    Es3Aead.open(opened.payloadKey, ChunkNonce.forIndex(index), Es3Chunking.aad(digest, index, index == count - 1), buf, 0, frameLen)
                } catch (e: Es3Exception.AuthenticationFailure) {
                    if (authenticatesAsNeighbour(opened.payloadKey, digest, buf, frameLen, index, count)) throw Es3Exception.ChunkSequence()
                    throw Es3Exception.AuthenticationFailure(index)
                }
                out.write(plain)
                plain.fill(0)
                done += plainLen
                progress?.onProgress(done, size)
                index++
            }
            if (input.read() != -1) throw Es3Exception.InvalidFormat("unexpected data after the final chunk")
        } finally {
            buf.fill(0)
        }
    }

    /** Failure-path diagnostic only: does this frame verify as the previous/next chunk? Then it is misplaced, not corrupted. */
    private fun authenticatesAsNeighbour(key: ByteArray, digest: ByteArray, buf: ByteArray, frameLen: Int, index: Long, count: Long): Boolean {
        for (j in longArrayOf(index - 1, index + 1)) {
            if (j < 0 || j >= count) continue
            try {
                Es3Aead.open(key, ChunkNonce.forIndex(j), Es3Chunking.aad(digest, j, j == count - 1), buf, 0, frameLen).fill(0)
                return true
            } catch (e: Es3Exception.AuthenticationFailure) { /* not this one */ }
        }
        return false
    }

    /** The name comes from authenticated, validated metadata; the canonical-parent check is defence in depth. */
    private fun uniqueTarget(dir: File, info: OriginalFileInfo): File {
        var n = 1
        var candidate = File(dir, info.fileName)
        while (candidate.exists()) {
            val suffix = if (info.extension.isEmpty()) "" else ".${info.extension}"
            candidate = File(dir, "${info.baseName} ($n)$suffix")
            n++
        }
        if (candidate.canonicalFile.parentFile != dir.canonicalFile) throw Es3Exception.CorruptedMetadata()
        return candidate
    }
}
