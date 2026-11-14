package dev.es3.core.format

import dev.es3.core.common.Es3Exception
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/** Reads up to [len] bytes, looping over short reads. Returns the number actually read (< len only at EOF). */
internal fun InputStream.readUpTo(buf: ByteArray, off: Int, len: Int): Int {
    var total = 0
    while (total < len) {
        val n = read(buf, off + total, len - total)
        if (n < 0) break
        total += n
    }
    return total
}

internal fun ioToEs3(e: IOException): Es3Exception =
    if (e.message?.contains("No space left", ignoreCase = true) == true) Es3Exception.InsufficientStorage(e)
    else Es3Exception.IoFailure(e)

/** Atomic rename where the filesystem supports it. Without [replace], an existing target is an error (checked first; small TOCTOU window documented). */
internal fun moveIntoPlace(tmp: File, target: File, replace: Boolean) {
    val src = tmp.toPath()
    val dst = target.toPath()
    if (!replace && Files.exists(dst)) throw Es3Exception.InvalidParameters("output file already exists")
    try {
        Files.move(src, dst, StandardCopyOption.ATOMIC_MOVE)
    } catch (e: AtomicMoveNotSupportedException) {
        if (replace) Files.move(src, dst, StandardCopyOption.REPLACE_EXISTING) else Files.move(src, dst)
    }
}
