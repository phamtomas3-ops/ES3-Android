package dev.es3.core.crypto

import dev.es3.core.common.Es3Exception
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import java.nio.CharBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Password -> 32-byte master key via Argon2id v1.3 (Bouncy Castle lightweight API), then purpose-specific
 * subkeys via HKDF-Expand (RFC 5869) with HMAC-SHA-256. Caller owns returned arrays and should zero them.
 */
object Es3Kdf {
    const val KEY_LEN = 32
    const val SALT_LEN = 32

    fun deriveMasterKey(password: CharArray, salt: ByteArray, params: Argon2idParams): ByteArray {
        params.validate()
        if (salt.size != SALT_LEN) throw Es3Exception.InvalidParameters("salt must be $SALT_LEN bytes")
        val pw = encodePassword(password)
        val argon = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(params.iterations)
            .withMemoryAsKB(params.memoryKiB)
            .withParallelism(params.parallelism)
            .withSalt(salt)
            .build()
        try {
            val out = ByteArray(KEY_LEN)
            val gen = Argon2BytesGenerator()
            gen.init(argon)
            gen.generateBytes(pw, out, 0, KEY_LEN)
            return out
        } finally {
            pw.fill(0)
            argon.clear()
        }
    }

    /** HKDF-Expand with a single output block: HMAC-SHA256(prk, info || 0x01). */
    fun expand(masterKey: ByteArray, info: String): ByteArray {
        if (masterKey.size != KEY_LEN) throw Es3Exception.InvalidParameters("master key must be 256 bits")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(masterKey, "HmacSHA256"))
        mac.update(info.toByteArray(Charsets.US_ASCII))
        mac.update(0x01.toByte())
        return mac.doFinal()
    }

    private fun encodePassword(password: CharArray): ByteArray {
        if (password.isEmpty()) throw Es3Exception.InvalidParameters("password must not be empty")
        val bb = try {
            Charsets.UTF_8.newEncoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).encode(CharBuffer.wrap(password))
        } catch (e: CharacterCodingException) {
            throw Es3Exception.InvalidParameters("password is not valid Unicode")
        }
        val out = ByteArray(bb.remaining())
        bb.get(out)
        if (bb.hasArray()) java.util.Arrays.fill(bb.array(), 0.toByte())
        return out
    }
}
