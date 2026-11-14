package dev.es3.core.crypto

import java.security.SecureRandom

/** The only source of randomness in the engine (salts). */
object Es3Random {
    private val rng = SecureRandom()
    fun bytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }
}
