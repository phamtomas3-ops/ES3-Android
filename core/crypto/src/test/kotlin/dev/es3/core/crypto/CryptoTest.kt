package dev.es3.core.crypto

import dev.es3.core.common.Es3Exception
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class CryptoTest {
    private val params = Argon2idParams(19_456, 2, 1) // policy minimum, valid for production files too
    private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

    @Test fun argon2idMatchesRfc9106Vector() {
        // RFC 9106 section 5.3 test vector, run through the same library/version the engine uses.
        val p = Argon2Parameters.Builder(Argon2Parameters.ARGON2_id).withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(3).withMemoryAsKB(32).withParallelism(4)
            .withSalt(ByteArray(16) { 2 }).withSecret(ByteArray(8) { 3 }).withAdditional(ByteArray(12) { 4 }).build()
        val out = ByteArray(32)
        Argon2BytesGenerator().also { it.init(p) }.generateBytes(ByteArray(32) { 1 }, out, 0, 32)
        assertEquals("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659", hex(out))
    }

    @Test fun hkdfExpandKnownAnswers() {
        val master = ByteArray(32) { it.toByte() }
        assertEquals("d904f14b209347326881cc1796bb546111f2c7693cd2e5d1e8ba51bf11995c54", hex(Es3Kdf.expand(master, "ES3/v1/metadata-key")))
        assertEquals("bd451f1634e2fe7e408a8fb3e47ba8686ae7d3df138e21928b44fc659174d091", hex(Es3Kdf.expand(master, "ES3/v1/payload-key")))
    }

    @Test fun kdfIsDeterministicAndSaltAndPasswordSensitive() {
        val salt = ByteArray(32) { 7 }
        val a = Es3Kdf.deriveMasterKey("pw".toCharArray(), salt, params)
        assertContentEquals(a, Es3Kdf.deriveMasterKey("pw".toCharArray(), salt, params))
        assertFalse(a.contentEquals(Es3Kdf.deriveMasterKey("pw2".toCharArray(), salt, params)))
        assertFalse(a.contentEquals(Es3Kdf.deriveMasterKey("pw".toCharArray(), ByteArray(32) { 8 }, params)))
    }

    @Test fun kdfRejectsBadInputs() {
        val salt = ByteArray(32)
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Kdf.deriveMasterKey(CharArray(0), salt, params) }
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Kdf.deriveMasterKey("x".toCharArray(), ByteArray(16), params) }
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Kdf.deriveMasterKey("\uD800".toCharArray(), salt, params) }
    }

    @Test fun parameterPolicyIsEnforced() {
        Argon2idParams.DEFAULT.validate()
        for (bad in listOf(
            Argon2idParams(1024, 3, 1), Argon2idParams(1_000_000, 3, 1), Argon2idParams(65_536, 1, 1),
            Argon2idParams(65_536, 11, 1), Argon2idParams(65_536, 3, 0), Argon2idParams(65_536, 3, 5)
        )) assertFailsWith<Es3Exception.InvalidParameters> { bad.validate() }
    }

    @Test fun aeadRoundTripAndTamperDetection() {
        val key = Es3Random.bytes(32); val nonce = ChunkNonce.forIndex(0); val aad = byteArrayOf(1, 2, 3)
        val pt = "hello".toByteArray()
        val sealed = Es3Aead.seal(key, nonce, aad, pt, 0, pt.size)
        assertEquals(pt.size + 16, sealed.size)
        assertContentEquals(pt, Es3Aead.open(key, nonce, aad, sealed, 0, sealed.size))
        assertFailsWith<Es3Exception.AuthenticationFailure> { Es3Aead.open(key, nonce, byteArrayOf(9), sealed, 0, sealed.size) }
        assertFailsWith<Es3Exception.AuthenticationFailure> { Es3Aead.open(key, ChunkNonce.forIndex(1), aad, sealed, 0, sealed.size) }
        val bad = sealed.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertFailsWith<Es3Exception.AuthenticationFailure> { Es3Aead.open(key, nonce, aad, bad, 0, bad.size) }
        assertFailsWith<Es3Exception.AuthenticationFailure> { Es3Aead.open(key, nonce, aad, sealed, 0, 5) }
    }

    @Test fun chunkNoncesAreUniqueAndWellFormed() {
        val seen = HashSet<String>()
        for (i in 0L until 200_000L) assertTrue(seen.add(hex(ChunkNonce.forIndex(i))), "nonce repeated at $i")
        assertEquals("000000000000000000000005", hex(ChunkNonce.forIndex(5)))
        assertEquals(12, ChunkNonce.forIndex(Long.MAX_VALUE).size)
        assertFailsWith<IllegalArgumentException> { ChunkNonce.forIndex(-1) }
    }

    @Test fun randomSaltsDiffer() {
        val seen = HashSet<String>()
        repeat(1000) { assertTrue(seen.add(hex(Es3Random.bytes(32)))) }
        assertNotEquals(hex(Es3Random.bytes(32)), hex(Es3Random.bytes(32)))
    }
}
