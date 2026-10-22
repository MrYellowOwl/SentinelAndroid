package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Test

class NicknamesTest {
    @Test fun keyPrefersMacLowercased() {
        assertEquals("aa:bb:cc", Nicknames.keyFor("AA:BB:CC", "192.168.1.5"))
        assertEquals("192.168.1.5", Nicknames.keyFor(null, "192.168.1.5"))
        assertEquals("192.168.1.5", Nicknames.keyFor("", "192.168.1.5"))
    }

    @Test fun displayNamePrefersNicknameThenScanName() {
        val dev = DeviceResult(
            ipAddress = "192.168.1.5",
            openPorts = emptyList(),
            identity = DeviceIdentity(name = "android-1234", mac = "AA:BB:CC")
        )
        assertEquals("Dad's laptop", Nicknames.displayName(dev, mapOf("aa:bb:cc" to "Dad's laptop")))
        assertEquals("android-1234", Nicknames.displayName(dev, emptyMap()))
        assertEquals("android-1234", Nicknames.displayName(dev, mapOf("aa:bb:cc" to "  ")))
    }

    @Test fun applyNamesRewritesSnapshotLabels() {
        val snaps = listOf(
            DeviceSnapshot("192.168.1.5", "aa:bb:cc", "android-1234", listOf(80)),
            DeviceSnapshot("192.168.1.6", null, null, listOf(22))
        )
        val out = Nicknames.applyNames(snaps, mapOf("aa:bb:cc" to "NAS", "192.168.1.6" to "Pi"))
        assertEquals("NAS", out[0].name)
        assertEquals("NAS", out[0].label)
        assertEquals("Pi", out[1].name)
        // Unchanged list returned as-is when no names.
        assertEquals(snaps, Nicknames.applyNames(snaps, emptyMap()))
    }
}
