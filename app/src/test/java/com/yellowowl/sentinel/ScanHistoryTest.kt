package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ScanHistoryTest {
    private fun netEntry(at: Long, devices: List<DeviceSnapshot>, high: Int = 0) = HistoryEntry(
        at = at, type = FindingSource.NETWORK, label = "192.168.1.0/24",
        deviceCount = devices.size,
        counts = mapOf(Severity.HIGH to high, Severity.MEDIUM to 0, Severity.LOW to 0, Severity.INFO to 0),
        devices = devices
    )

    @Test fun jsonRoundTripsIncludingDevices() {
        val entries = listOf(
            netEntry(2000, listOf(DeviceSnapshot("192.168.1.10", "aa:bb", "NAS", listOf(22, 445)))),
            netEntry(1000, listOf(DeviceSnapshot("192.168.1.1", null, null, listOf(80))))
        )
        val back = ScanHistoryCodec.parse(ScanHistoryCodec.toJson(entries))
        assertEquals(2, back.size)
        assertEquals(2000, back[0].at)
        assertEquals("NAS", back[0].devices[0].name)
        assertEquals(listOf(22, 445), back[0].devices[0].ports)
        assertEquals("aa:bb", back[0].devices[0].mac)
    }

    @Test fun capsAtMaxEntries() {
        val many = (1..100).map { netEntry(it.toLong(), emptyList()) }
        val json = ScanHistoryCodec.toJson(many)
        assertEquals(ScanHistoryCodec.MAX_ENTRIES, ScanHistoryCodec.parse(json).size)
    }

    @Test fun entryFromFindingsCountsSeverities() {
        val findings = listOf(
            Finding(title = "a", severity = Severity.HIGH, source = FindingSource.NETWORK, scope = "s", target = "t", details = "", remediation = ""),
            Finding(title = "b", severity = Severity.LOW, source = FindingSource.NETWORK, scope = "s", target = "t2", details = "", remediation = "")
        )
        val e = ScanHistoryCodec.entryFromFindings(1L, FindingSource.NETWORK, "192.168.1.0/24", findings,
            listOf(DeviceSnapshot("192.168.1.2")))
        assertEquals(1, e.count(Severity.HIGH))
        assertEquals(1, e.count(Severity.LOW))
        assertEquals(2, e.issueCount)
        assertEquals(1, e.deviceCount)
    }

    @Test fun diffAgainstPreviousDetectsChanges() {
        val entries = listOf(
            netEntry(2000, listOf(DeviceSnapshot("192.168.1.10", "aa", "NAS", listOf(22, 445)))),  // newest
            netEntry(1000, listOf(DeviceSnapshot("192.168.1.11", "bb", "Old", listOf(22))))         // older
        )
        val diff = ScanHistoryCodec.diffAgainstPrevious(entries, entries[0])
        assertNotNull(diff)
        assertEquals(1, diff!!.newDevices.size)   // aa appeared
        assertEquals(1, diff.goneDevices.size)    // bb left
    }

    @Test fun diffReturnsNullForWebOrFirstScan() {
        val web = HistoryEntry(1L, FindingSource.WEB, "example.com", 0, emptyMap())
        assertNull(ScanHistoryCodec.diffAgainstPrevious(listOf(web), web))
        val lone = netEntry(1000, listOf(DeviceSnapshot("192.168.1.1")))
        assertNull(ScanHistoryCodec.diffAgainstPrevious(listOf(lone), lone))
    }

    @Test fun parseRejectsJunk() {
        assertTrue(ScanHistoryCodec.parse("not json").isEmpty())
    }
}
