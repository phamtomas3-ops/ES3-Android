package dev.es3.legacy.easysave3
import kotlin.test.Test
import kotlin.test.assertEquals

class LegacyStatusTest {
    @Test fun legacyIsUnverifiedUntilSamplesPass() {
        assertEquals("LEGACY COMPATIBILITY: UNVERIFIED", LegacyStatus.current.label)
    }
}
