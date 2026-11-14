package dev.es3.legacy.easysave3

enum class LegacyCompat(val label: String) {
    UNVERIFIED("LEGACY COMPATIBILITY: UNVERIFIED"),
    VERIFIED("LEGACY COMPATIBILITY: VERIFIED")
}

object LegacyStatus {
    /** Stays UNVERIFIED until a test suite with legitimate sample saves passes. */
    val current: LegacyCompat = LegacyCompat.UNVERIFIED
}
