package dev.es3.core.common

/**
 * Progress callback, invoked after each chunk. Throwing a [java.util.concurrent.CancellationException]
 * from it cancels the operation; the engine cleans up temporary files and rethrows.
 */
fun interface Es3Progress {
    fun onProgress(processedBytes: Long, totalBytes: Long)
}
