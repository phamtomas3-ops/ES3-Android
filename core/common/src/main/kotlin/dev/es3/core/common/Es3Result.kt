package dev.es3.core.common

sealed interface Es3Result<out T> {
    data class Success<T>(val value: T) : Es3Result<T>
    data class Failure(val error: Es3Exception) : Es3Result<Nothing>
}

/** Converts engine exceptions into a result value for UI code. Other exceptions (e.g. cancellation) propagate. */
inline fun <T> es3Catching(block: () -> T): Es3Result<T> =
    try { Es3Result.Success(block()) } catch (e: Es3Exception) { Es3Result.Failure(e) }
