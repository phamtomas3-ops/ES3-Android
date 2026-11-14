package dev.es3.core.common

import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction

/** Name/extension/size of the file inside an ES.3 container. Validated so it can never express a path. */
data class OriginalFileInfo(val baseName: String, val extension: String, val size: Long) {
    init {
        if (size < 0) throw Es3Exception.InvalidParameters("original size is negative")
        check(baseName, MAX_BASE_BYTES, allowEmpty = false)
        check(extension, MAX_EXT_BYTES, allowEmpty = true)
        if (baseName == "." || baseName == "..") throw Es3Exception.InvalidParameters("reserved file name")
        if (extension.contains('.')) throw Es3Exception.InvalidParameters("extension contains a dot")
        if (utf8Length(fileName) > MAX_FILE_NAME_BYTES) throw Es3Exception.InvalidParameters("file name too long")
    }

    val fileName: String get() = if (extension.isEmpty()) baseName else "$baseName.$extension"

    companion object {
        const val MAX_BASE_BYTES = 255
        const val MAX_EXT_BYTES = 32
        const val MAX_FILE_NAME_BYTES = 255

        /** Splits at the last dot ("save.dat" -> "save"+"dat"; ".hidden", "a." and "noext" keep an empty extension). */
        fun fromFileName(fileName: String, size: Long): OriginalFileInfo {
            val dot = fileName.lastIndexOf('.')
            return if (dot > 0 && dot < fileName.length - 1)
                OriginalFileInfo(fileName.substring(0, dot), fileName.substring(dot + 1), size)
            else OriginalFileInfo(fileName, "", size)
        }

        private fun check(s: String, maxBytes: Int, allowEmpty: Boolean) {
            if (!allowEmpty && s.isEmpty()) throw Es3Exception.InvalidParameters("empty file name")
            for (c in s) {
                if (c == '/' || c == '\\' || c < ' ' || c == '\u007f')
                    throw Es3Exception.InvalidParameters("file name contains a forbidden character")
            }
            if (utf8Length(s) > maxBytes) throw Es3Exception.InvalidParameters("file name part too long")
        }

        private fun utf8Length(s: String): Int = try {
            Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(s)).remaining()
        } catch (e: CharacterCodingException) {
            throw Es3Exception.InvalidParameters("file name is not valid Unicode")
        }
    }
}
