package dev.es3.core.format

import dev.es3.core.common.Es3Exception
import dev.es3.core.common.OriginalFileInfo
import java.nio.BufferUnderflowException
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/**
 * Metadata plaintext (encrypted + authenticated inside the header), big-endian:
 *   u8 compression_id | u64 original_size | u16 name_len | name (UTF-8) | u8 ext_len | ext (UTF-8)
 */
internal object Es3Metadata {
    fun encode(info: OriginalFileInfo): ByteArray {
        val name = info.baseName.toByteArray(Charsets.UTF_8)
        val ext = info.extension.toByteArray(Charsets.UTF_8)
        val bb = ByteBuffer.allocate(1 + 8 + 2 + name.size + 1 + ext.size)
        bb.put(Es3Format.COMPRESSION_NONE.toByte())
        bb.putLong(info.size)
        bb.putShort(name.size.toShort())
        bb.put(name)
        bb.put(ext.size.toByte())
        bb.put(ext)
        return bb.array()
    }

    fun decode(plain: ByteArray): OriginalFileInfo {
        try {
            val bb = ByteBuffer.wrap(plain)
            val compression = bb.get().toInt() and 0xFF
            if (compression != Es3Format.COMPRESSION_NONE) throw Es3Exception.UnsupportedFeature("compression method $compression")
            val size = bb.long
            val nameLen = bb.short.toInt() and 0xFFFF
            if (nameLen > OriginalFileInfo.MAX_BASE_BYTES || nameLen > bb.remaining()) throw Es3Exception.CorruptedMetadata()
            val name = utf8(bb, nameLen)
            val extLen = bb.get().toInt() and 0xFF
            if (extLen > OriginalFileInfo.MAX_EXT_BYTES || extLen > bb.remaining()) throw Es3Exception.CorruptedMetadata()
            val ext = utf8(bb, extLen)
            if (bb.hasRemaining()) throw Es3Exception.CorruptedMetadata()
            return OriginalFileInfo(name, ext, size)
        } catch (e: BufferUnderflowException) {
            throw Es3Exception.CorruptedMetadata()
        } catch (e: CharacterCodingException) {
            throw Es3Exception.CorruptedMetadata()
        } catch (e: Es3Exception.InvalidParameters) {
            throw Es3Exception.CorruptedMetadata()
        }
    }

    private fun utf8(bb: ByteBuffer, len: Int): String {
        val raw = ByteArray(len)
        bb.get(raw)
        return Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(raw)).toString()
    }
}
