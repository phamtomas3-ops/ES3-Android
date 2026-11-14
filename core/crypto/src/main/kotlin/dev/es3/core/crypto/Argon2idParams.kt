package dev.es3.core.crypto

import dev.es3.core.common.Es3Exception

/**
 * Argon2id cost parameters. Policy (also enforced on files we READ, so a hostile file cannot demand
 * unbounded memory, and a downgraded file is rejected rather than silently accepted):
 *  - memory   : 19 456 KiB (19 MiB, OWASP minimum) .. 262 144 KiB (256 MiB)
 *  - passes   : 2 .. 10
 *  - lanes    : 1 .. 4
 * Default for new files: 64 MiB, 3 passes, 1 lane.
 */
data class Argon2idParams(val memoryKiB: Int, val iterations: Int, val parallelism: Int) {
    fun validate() {
        if (memoryKiB !in MIN_MEMORY_KIB..MAX_MEMORY_KIB) throw Es3Exception.InvalidParameters("Argon2id memory cost out of range")
        if (iterations !in MIN_ITERATIONS..MAX_ITERATIONS) throw Es3Exception.InvalidParameters("Argon2id iteration count out of range")
        if (parallelism !in MIN_PARALLELISM..MAX_PARALLELISM) throw Es3Exception.InvalidParameters("Argon2id parallelism out of range")
    }

    companion object {
        const val MIN_MEMORY_KIB = 19_456
        const val MAX_MEMORY_KIB = 262_144
        const val MIN_ITERATIONS = 2
        const val MAX_ITERATIONS = 10
        const val MIN_PARALLELISM = 1
        const val MAX_PARALLELISM = 4
        val DEFAULT = Argon2idParams(memoryKiB = 65_536, iterations = 3, parallelism = 1)
    }
}
