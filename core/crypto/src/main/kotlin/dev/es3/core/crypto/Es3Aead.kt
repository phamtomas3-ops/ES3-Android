package dev.es3.core.crypto

import dev.es3.core.common.Es3Exception
import java.security.GeneralSecurityException
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** AES-256-GCM with a 128-bit tag. Output of [seal] is ciphertext || tag. Callers must never reuse (key, nonce). */
object Es3Aead {
    const val KEY_LEN = 32
    const val NONCE_LEN = 12
    const val TAG_LEN = 16
    private const val TRANSFORM = "AES/GCM/NoPadding"

    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray, offset: Int, length: Int): ByteArray {
        checkSizes(key, nonce)
        try {
            val c = Cipher.getInstance(TRANSFORM)
            c.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
            c.updateAAD(aad)
            return c.doFinal(plaintext, offset, length)
        } catch (e: GeneralSecurityException) {
            throw Es3Exception.InvalidParameters("encryption failed", e)
        }
    }

    /** @throws Es3Exception.AuthenticationFailure if the tag does not verify. Never returns unauthenticated data. */
    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, sealed: ByteArray, offset: Int, length: Int): ByteArray {
        checkSizes(key, nonce)
        if (length < TAG_LEN) throw Es3Exception.AuthenticationFailure()
        try {
            val c = Cipher.getInstance(TRANSFORM)
            c.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(TAG_LEN * 8, nonce))
            c.updateAAD(aad)
            return c.doFinal(sealed, offset, length)
        } catch (e: AEADBadTagException) {
            throw Es3Exception.AuthenticationFailure()
        } catch (e: GeneralSecurityException) {
            throw Es3Exception.AuthenticationFailure()
        }
    }

    private fun checkSizes(key: ByteArray, nonce: ByteArray) {
        if (key.size != KEY_LEN) throw Es3Exception.InvalidParameters("key must be 256 bits")
        if (nonce.size != NONCE_LEN) throw Es3Exception.InvalidParameters("nonce must be 96 bits")
    }
}
