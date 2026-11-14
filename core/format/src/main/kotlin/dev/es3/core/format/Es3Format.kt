package dev.es3.core.format

/** Constants of ES.3 container format version 1. See docs/ES3_FORMAT.md. */
object Es3Format {
    /** 0x89 'E' 'S' '3' CR LF 0x1A LF — PNG-style: detects text-mode/line-ending mangling. */
    val MAGIC: ByteArray = byteArrayOf(0x89.toByte(), 'E'.code.toByte(), 'S'.code.toByte(), '3'.code.toByte(), 0x0D, 0x0A, 0x1A, 0x0A)
    const val VERSION_1 = 1
    const val KDF_ARGON2ID = 1
    const val AEAD_AES_256_GCM = 1
    const val COMPRESSION_NONE = 0
    const val SALT_LEN = 32
    const val TAG_LEN = 16
    const val NONCE_LEN = 12
    /** Fixed-size part of the header: everything before the metadata ciphertext. */
    const val PRE_META_SIZE = 64
    const val MIN_CHUNK_SIZE = 4 * 1024
    const val MAX_CHUNK_SIZE = 64 * 1024 * 1024
    const val DEFAULT_CHUNK_SIZE = 1024 * 1024
    const val MIN_META_PLAIN = 13
    const val MAX_META_CT = 1024
    const val INFO_METADATA_KEY = "ES3/v1/metadata-key"
    const val INFO_PAYLOAD_KEY = "ES3/v1/payload-key"
}
