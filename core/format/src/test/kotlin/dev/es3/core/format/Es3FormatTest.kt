package dev.es3.core.format

import dev.es3.core.common.Es3Exception
import dev.es3.core.common.OriginalFileInfo
import dev.es3.core.crypto.Argon2idParams
import dev.es3.core.crypto.ChunkNonce
import dev.es3.core.crypto.Es3Aead
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.util.zip.CRC32
import kotlin.io.path.createTempDirectory
import kotlin.random.Random
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Es3FormatTest {
    private val pw = "correct horse battery staple"
    private val kdf = Argon2idParams(19_456, 2, 1) // policy minimum; production validation is NOT relaxed
    private val opts = EncryptOptions(chunkSize = 4096, kdf = kdf)
    private lateinit var outDir: File

    @BeforeTest fun setUp() { outDir = createTempDirectory("es3test").toFile() }
    @AfterTest fun tearDown() { outDir.deleteRecursively() }

    private fun enc(plain: ByteArray, name: String = "save.dat", password: String = pw, o: EncryptOptions = opts): ByteArray {
        val out = ByteArrayOutputStream()
        Es3Encryptor.encrypt(ByteArrayInputStream(plain), OriginalFileInfo.fromFileName(name, plain.size.toLong()), password.toCharArray(), out, o)
        return out.toByteArray()
    }
    private fun dec(cipher: ByteArray, password: String = pw) =
        Es3Decryptor.decryptToFile(ByteArrayInputStream(cipher), password.toCharArray(), outDir)
    private fun assertNoOutput() = assertEquals(0, outDir.list()!!.size, "failed decryption must leave no output or temp files")
    private fun headerLen(c: ByteArray) = 64 + ByteBuffer.wrap(c, 60, 4).int + 4
    private fun flip(c: ByteArray, i: Int) = c.copyOf().also { it[i] = (it[i].toInt() xor 1).toByte() }
    private fun fixCrc(b: ByteArray): ByteArray {
        val end = 64 + ByteBuffer.wrap(b, 60, 4).int
        val crc = CRC32().also { it.update(b, 0, end) }.value
        ByteBuffer.wrap(b, end, 4).putInt(crc.toInt())
        return b
    }
    private fun frames(c: ByteArray, plainLen: Int, chunk: Int): List<ByteArray> {
        val h = headerLen(c); val out = ArrayList<ByteArray>(); var pos = h
        while (pos < c.size) { val n = minOf(chunk + 16, c.size - pos); out.add(c.copyOfRange(pos, pos + n)); pos += n }
        return out
    }
    private fun join(c: ByteArray, parts: List<ByteArray>): ByteArray {
        val o = ByteArrayOutputStream(); o.write(c, 0, headerLen(c)); parts.forEach { o.write(it) }; return o.toByteArray()
    }
    private val data = Random(42).nextBytes(14_336) // 3.5 chunks of 4096 -> 4 frames

    // ---- required tests 1-3: round trips ----
    @Test fun smallRoundTrip() {
        val plain = "hello ES.3".toByteArray()
        val r = dec(enc(plain, "slot1.sav"))
        assertContentEquals(plain, r.file.readBytes())
        assertEquals("slot1", r.info.baseName); assertEquals("sav", r.info.extension); assertEquals(plain.size.toLong(), r.info.size)
        assertEquals("slot1.sav", r.file.name)
    }

    @Test fun emptyFileRoundTrip() {
        val c = enc(ByteArray(0), "empty.bin")
        assertEquals(headerLen(c) + 16, c.size) // one empty final chunk = tag only
        val r = dec(c)
        assertEquals(0L, r.file.length()); assertEquals(0L, r.info.size)
    }

    @Test fun chunkBoundarySizesRoundTrip() {
        for (n in listOf(1, 4095, 4096, 4097, 8192, 12_289)) {
            val plain = Random(n).nextBytes(n)
            val r = dec(enc(plain)); assertContentEquals(plain, r.file.readBytes(), "size $n")
        }
    }

    @Test fun differentFileTypesAndNames() {
        for (name in listOf("a.json", "b.es3sav", "noext", ".hidden", "ünï cödé.dat", "x.tar.gz")) {
            val r = dec(enc("x".toByteArray(), name)); assertEquals(name, r.info.fileName)
        }
    }

    @Test fun largeFileRoundTripWithDefaultChunkSize() {
        val plain = Random(7).nextBytes(20 * 1024 * 1024)
        val file = File(outDir, "big.es3")
        Es3Encryptor.encryptToFile(ByteArrayInputStream(plain), OriginalFileInfo.fromFileName("big.bin", plain.size.toLong()), pw.toCharArray(), file,
            EncryptOptions(kdf = kdf))
        val r = FileInputStream(file).use { Es3Decryptor.decryptToFile(it, pw.toCharArray(), outDir) }
        assertContentEquals(plain, r.file.readBytes())
    }

    // ---- 4: wrong password ----
    @Test fun wrongPasswordRejected() {
        val c = enc(data)
        assertFailsWith<Es3Exception.IncorrectPassword> { dec(c, "wrong") }
        assertFailsWith<Es3Exception.IncorrectPassword> { Es3Decryptor.readMetadata(ByteArrayInputStream(c), "wrong".toCharArray()) }
        assertNoOutput()
    }

    @Test fun readMetadataWithCorrectPassword() {
        val i = Es3Decryptor.readMetadata(ByteArrayInputStream(enc(data, "m.sav")), pw.toCharArray())
        assertEquals("m.sav", i.fileName); assertEquals(data.size.toLong(), i.size)
    }

    // ---- 5, 6: header / metadata modification ----
    @Test fun modifiedHeaderDetected() {
        val c = enc(data)
        assertFailsWith<Es3Exception.InvalidFormat> { dec(flip(c, 0)) }
        assertFailsWith<Es3Exception.CorruptedHeader> { dec(flip(c, 30)) }            // salt, CRC stale
        assertFailsWith<Es3Exception.IncorrectPassword> { dec(fixCrc(flip(c, 30))) }   // salt, CRC fixed -> different key
        assertFailsWith<Es3Exception.IncorrectPassword> { dec(fixCrc(flip(c, 17))) }   // Argon2 memory
        assertFailsWith<Es3Exception.IncorrectPassword> { dec(fixCrc(flip(c, 58))) }   // chunk size (AAD of metadata)
        assertNoOutput()
    }

    @Test fun modifiedMetadataDetected() {
        val c = enc(data)
        assertFailsWith<Es3Exception.CorruptedHeader> { dec(flip(c, 66)) }
        assertFailsWith<Es3Exception.IncorrectPassword> { dec(fixCrc(flip(c, 66))) }
        assertNoOutput()
    }

    @Test fun unsupportedFlagsAndAlgorithmsRejected() {
        val c = enc(data)
        assertFailsWith<Es3Exception.UnsupportedFeature> { dec(c.copyOf().also { it[11] = 1 }) }
        assertFailsWith<Es3Exception.UnsupportedFeature> { dec(c.copyOf().also { it[12] = 2 }) }
        assertFailsWith<Es3Exception.UnsupportedFeature> { dec(c.copyOf().also { it[13] = 2 }) }
        assertNoOutput()
    }

    // ---- 7: payload modification ----
    @Test fun modifiedPayloadNeverAccepted() {
        val c = enc(data); val h = headerLen(c)
        for (pos in listOf(h, h + 10, h + 4096 + 16 + 5, c.size - 1, c.size - 17)) {
            val e = assertFailsWith<Es3Exception.AuthenticationFailure> { dec(flip(c, pos)) }
            assertTrue(e.chunkIndex != null)
        }
        assertNoOutput()
    }

    // ---- 8: truncation ----
    @Test fun truncationDetectedAtEveryRegion() {
        val c = enc(data); val h = headerLen(c)
        for (cut in listOf(0, 3, 7, 8, 9, 30, 63, 70, h - 1, h, h + 100, c.size - 17, c.size - 1)) {
            assertFailsWith<Es3Exception> { dec(c.copyOf(cut)) }
        }
        for (cut in listOf(8, 9, 30, 63, 70, h - 1, h, h + 100, c.size - 1)) assertFailsWith<Es3Exception.TruncatedInput> { dec(c.copyOf(cut)) }
        assertNoOutput()
    }

    @Test fun trailingDataRejected() {
        assertFailsWith<Es3Exception.InvalidFormat> { dec(enc(data) + byteArrayOf(0)) }
        assertNoOutput()
    }

    // ---- 9, 10, 11: chunk manipulation ----
    @Test fun missingChunkDetected() {
        val c = enc(data); val f = frames(c, data.size, 4096); assertEquals(4, f.size)
        val e = assertFailsWith<Es3Exception> { dec(join(c, listOf(f[0], f[2], f[3]))) }
        assertTrue(e is Es3Exception.ChunkSequence || e is Es3Exception.TruncatedInput || e is Es3Exception.AuthenticationFailure)
        assertFailsWith<Es3Exception.TruncatedInput> { dec(join(c, f.take(3))) }          // final chunk removed
        assertNoOutput()
    }

    @Test fun reorderedChunksDetected() {
        val c = enc(data); val f = frames(c, data.size, 4096)
        assertFailsWith<Es3Exception.ChunkSequence> { dec(join(c, listOf(f[0], f[2], f[1], f[3]))) }
        assertFailsWith<Es3Exception> { dec(join(c, listOf(f[2], f[1], f[0], f[3]))) }
        assertNoOutput()
    }

    @Test fun duplicatedChunkDetected() {
        val c = enc(data); val f = frames(c, data.size, 4096)
        assertFailsWith<Es3Exception.ChunkSequence> { dec(join(c, listOf(f[0], f[1], f[1], f[2], f[3]))) }
        assertNoOutput()
    }

    // ---- 12: versions ----
    @Test fun unsupportedVersionRejected() {
        val c = enc(data)
        for (v in listOf(0, 2, 255, 0x0100)) {
            val e = assertFailsWith<Es3Exception.UnsupportedVersion> { dec(c.copyOf().also { it[8] = (v shr 8).toByte(); it[9] = v.toByte() }) }
            assertEquals(v, e.version)
        }
        assertNoOutput()
    }

    // ---- 13: invalid parameters ----
    @Test fun invalidParametersRejected() {
        val info = OriginalFileInfo.fromFileName("a.b", 1)
        val src = { ByteArrayInputStream(ByteArray(1)) }
        val sink = { ByteArrayOutputStream() }
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Encryptor.encrypt(src(), info, pw.toCharArray(), sink(), EncryptOptions(100, kdf)) }
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Encryptor.encrypt(src(), info, pw.toCharArray(), sink(), EncryptOptions(128 * 1024 * 1024, kdf)) }
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Encryptor.encrypt(src(), info, pw.toCharArray(), sink(), EncryptOptions(4096, Argon2idParams(1024, 2, 1))) }
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Encryptor.encrypt(src(), info, CharArray(0), sink(), opts) }
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Encryptor.encrypt(ByteArrayInputStream(ByteArray(0)), info, pw.toCharArray(), sink(), opts) } // shorter than declared
        assertFailsWith<Es3Exception.InvalidParameters> { Es3Encryptor.encrypt(ByteArrayInputStream(ByteArray(5)), info, pw.toCharArray(), sink(), opts) } // longer
        for (bad in listOf("a/b", "..", "", "x\u0000y", "a\\b", "a".repeat(300)))
            assertFailsWith<Es3Exception.InvalidParameters> { OriginalFileInfo.fromFileName(bad, 0) }
        assertFailsWith<Es3Exception.InvalidParameters> { OriginalFileInfo("a", "b", -1) }
    }

    @Test fun failedEncryptionLeavesNoFiles() {
        val dest = File(outDir, "x.es3")
        assertFailsWith<Es3Exception.InvalidParameters> {
            Es3Encryptor.encryptToFile(ByteArrayInputStream(ByteArray(2)), OriginalFileInfo.fromFileName("a.b", 10), pw.toCharArray(), dest, opts)
        }
        assertFalse(dest.exists()); assertNoOutput()
    }

    @Test fun encryptionNeverOverwritesByDefault() {
        val dest = File(outDir, "x.es3"); dest.writeText("existing")
        assertFailsWith<Es3Exception.InvalidParameters> {
            Es3Encryptor.encryptToFile(ByteArrayInputStream(ByteArray(1)), OriginalFileInfo.fromFileName("a.b", 1), pw.toCharArray(), dest, opts)
        }
        assertEquals("existing", dest.readText())
    }

    @Test fun decryptionNeverOverwritesExistingFile() {
        val c = enc("new".toByteArray(), "s.dat")
        File(outDir, "s.dat").writeText("old")
        val r = dec(c)
        assertEquals("old", File(outDir, "s.dat").readText()); assertEquals("s (1).dat", r.file.name); assertEquals("new", r.file.readText())
    }

    // ---- 14: randomness ----
    @Test fun sameInputGivesDifferentCiphertext() {
        val a = enc(data); val b = enc(data)
        assertFalse(a.contentEquals(b)); assertFalse(a.copyOfRange(24, 56).contentEquals(b.copyOfRange(24, 56)), "salts must differ")
        assertEquals(a.size, b.size)
        val salts = HashSet<String>(); repeat(15) { salts.add(enc(ByteArray(1)).copyOfRange(24, 56).joinToString()) }
        assertEquals(15, salts.size)
    }

    // ---- nonce / finalization ----
    @Test fun finalFlagAndIndexAreAuthenticated() {
        val key = ByteArray(32) { 1 }; val digest = ByteArray(32) { 2 }; val pt = ByteArray(10)
        val sealed = Es3Aead.seal(key, ChunkNonce.forIndex(3), Es3Chunking.aad(digest, 3, true), pt, 0, pt.size)
        Es3Aead.open(key, ChunkNonce.forIndex(3), Es3Chunking.aad(digest, 3, true), sealed, 0, sealed.size)
        assertFailsWith<Es3Exception.AuthenticationFailure> { Es3Aead.open(key, ChunkNonce.forIndex(3), Es3Chunking.aad(digest, 3, false), sealed, 0, sealed.size) }
        assertFailsWith<Es3Exception.AuthenticationFailure> { Es3Aead.open(key, ChunkNonce.forIndex(3), Es3Chunking.aad(digest, 4, true), sealed, 0, sealed.size) }
        assertFailsWith<Es3Exception.AuthenticationFailure> { Es3Aead.open(key, ChunkNonce.forIndex(3), Es3Chunking.aad(ByteArray(32) { 9 }, 3, true), sealed, 0, sealed.size) }
    }

    @Test fun chunkMathIsOverflowSafe() {
        assertEquals(1L, Es3Chunking.chunkCount(0, 4096)); assertEquals(1L, Es3Chunking.chunkCount(4096, 4096))
        assertEquals(2L, Es3Chunking.chunkCount(4097, 4096))
        assertEquals(Long.MAX_VALUE / 4096 + 1, Es3Chunking.chunkCount(Long.MAX_VALUE, 4096))
        assertEquals(4096, Es3Chunking.plainLength(0, 2, 4097, 4096)); assertEquals(1, Es3Chunking.plainLength(1, 2, 4097, 4096))
    }

    // ---- 15: bounded memory ----
    private class PatternStream(private var remaining: Long) : InputStream() {
        private var counter = 0L
        override fun read(): Int { if (remaining <= 0) return -1; remaining--; return ((counter++ * 31) and 0xFF).toInt() }
        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (remaining <= 0) return -1
            val n = minOf(len.toLong(), remaining).toInt()
            for (i in 0 until n) b[off + i] = ((counter++ * 31) and 0xFF).toByte()
            remaining -= n; return n
        }
    }
    private fun sha(i: InputStream): String { val d = MessageDigest.getInstance("SHA-256"); val b = ByteArray(65536)
        while (true) { val n = i.read(b); if (n < 0) break; d.update(b, 0, n) }; return d.digest().joinToString("") { "%02x".format(it) } }

    @Test fun streamingMemoryIsBounded() {
        val size = 256L * 1024 * 1024
        // The test JVM heap is capped at 160 MiB in core/format/build.gradle.kts, so buffering the file would throw OutOfMemoryError.
        assertTrue(Runtime.getRuntime().maxMemory() < size, "run with the capped heap configured in build.gradle.kts")
        val file = File(outDir, "huge.es3")
        Es3Encryptor.encryptToFile(PatternStream(size), OriginalFileInfo.fromFileName("huge.bin", size), pw.toCharArray(), file, EncryptOptions(kdf = kdf))
        val r = FileInputStream(file).use { Es3Decryptor.decryptToFile(it, pw.toCharArray(), outDir) }
        assertEquals(size, r.file.length())
        assertEquals(sha(PatternStream(size)), FileInputStream(r.file).use { sha(it) })
    }
}
