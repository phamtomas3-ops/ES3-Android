package dev.es3.core.format

import dev.es3.core.common.Es3Exception
import dev.es3.core.crypto.Argon2idParams
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.zip.CRC32

/** Parsed header. [preMeta] = bytes before the metadata ciphertext (AAD of the metadata); [prefix] = preMeta || metaCiphertext. */
internal class Es3Header(
    val kdf: Argon2idParams,
    val salt: ByteArray,
    val chunkSize: Int,
    val preMeta: ByteArray,
    val metaCiphertext: ByteArray
) {
    val prefix: ByteArray get() = preMeta + metaCiphertext
    /** SHA-256 over the whole header (without CRC); bound into every chunk's AAD. */
    fun digest(): ByteArray = MessageDigest.getInstance("SHA-256").digest(prefix)
}

internal object Es3HeaderCodec {
    fun encodePreMeta(params: Argon2idParams, salt: ByteArray, chunkSize: Int, metaCiphertextLen: Int): ByteArray {
        val b = ByteBuffer.allocate(Es3Format.PRE_META_SIZE)
        b.put(Es3Format.MAGIC)
        b.putShort(Es3Format.VERSION_1.toShort())
        b.putShort(0) // flags, must be zero in v1
        b.put(Es3Format.KDF_ARGON2ID.toByte())
        b.put(Es3Format.AEAD_AES_256_GCM.toByte())
        b.putInt(params.memoryKiB)
        b.putInt(params.iterations)
        b.put(params.parallelism.toByte())
        b.put(Es3Format.SALT_LEN.toByte())
        b.put(salt)
        b.putInt(chunkSize)
        b.putInt(metaCiphertextLen)
        return b.array()
    }

    /** Full header bytes: preMeta || metaCiphertext || CRC-32 (big-endian) of those bytes. */
    fun finish(preMeta: ByteArray, metaCiphertext: ByteArray): ByteArray {
        val prefix = preMeta + metaCiphertext
        val crc = CRC32().also { it.update(prefix) }.value
        return prefix + ByteBuffer.allocate(4).putInt(crc.toInt()).array()
    }

    fun read(input: InputStream): Es3Header {
        val pre = ByteArray(Es3Format.PRE_META_SIZE)
        val n = input.readUpTo(pre, 0, 8)
        for (i in 0 until n) if (pre[i] != Es3Format.MAGIC[i]) throw Es3Exception.InvalidFormat("bad signature")
        if (n < 8) throw Es3Exception.TruncatedInput()

        if (input.readUpTo(pre, 8, 2) < 2) throw Es3Exception.TruncatedInput()
        val version = ((pre[8].toInt() and 0xFF) shl 8) or (pre[9].toInt() and 0xFF)
        if (version != Es3Format.VERSION_1) throw Es3Exception.UnsupportedVersion(version)

        if (input.readUpTo(pre, 10, Es3Format.PRE_META_SIZE - 10) < Es3Format.PRE_META_SIZE - 10) throw Es3Exception.TruncatedInput()
        val bb = ByteBuffer.wrap(pre)
        bb.position(10)
        val flags = bb.short.toInt() and 0xFFFF
        val kdfId = bb.get().toInt() and 0xFF
        val aeadId = bb.get().toInt() and 0xFF
        if (flags != 0) throw Es3Exception.UnsupportedFeature("header flags")
        if (kdfId != Es3Format.KDF_ARGON2ID) throw Es3Exception.UnsupportedFeature("key derivation function $kdfId")
        if (aeadId != Es3Format.AEAD_AES_256_GCM) throw Es3Exception.UnsupportedFeature("cipher $aeadId")

        val m = bb.int.toLong() and 0xFFFFFFFFL
        val t = bb.int.toLong() and 0xFFFFFFFFL
        val p = bb.get().toInt() and 0xFF
        val saltLen = bb.get().toInt() and 0xFF
        if (m > Int.MAX_VALUE || t > Int.MAX_VALUE || saltLen != Es3Format.SALT_LEN) throw Es3Exception.CorruptedHeader()
        val params = Argon2idParams(m.toInt(), t.toInt(), p)
        try { params.validate() } catch (e: Es3Exception.InvalidParameters) { throw Es3Exception.CorruptedHeader() }
        val salt = ByteArray(saltLen)
        bb.get(salt)
        val chunkSizeL = bb.int.toLong() and 0xFFFFFFFFL
        val metaLenL = bb.int.toLong() and 0xFFFFFFFFL
        if (chunkSizeL < Es3Format.MIN_CHUNK_SIZE || chunkSizeL > Es3Format.MAX_CHUNK_SIZE) throw Es3Exception.CorruptedHeader()
        if (metaLenL < Es3Format.MIN_META_PLAIN + Es3Format.TAG_LEN || metaLenL > Es3Format.MAX_META_CT) throw Es3Exception.CorruptedHeader()

        val metaCt = ByteArray(metaLenL.toInt())
        if (input.readUpTo(metaCt, 0, metaCt.size) < metaCt.size) throw Es3Exception.TruncatedInput()
        val crcBytes = ByteArray(4)
        if (input.readUpTo(crcBytes, 0, 4) < 4) throw Es3Exception.TruncatedInput()
        val stored = ByteBuffer.wrap(crcBytes).int.toLong() and 0xFFFFFFFFL
        val actual = CRC32().also { it.update(pre); it.update(metaCt) }.value
        // CRC-32 is an accidental-corruption check only; authenticity comes from the metadata GCM tag.
        if (stored != actual) throw Es3Exception.CorruptedHeader()
        return Es3Header(params, salt, chunkSizeL.toInt(), pre, metaCt)
    }
}
