package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WalkthroughTest {
    private fun netFinding(ip: String, port: Int, title: String, created: Long = 1) = Finding(
        title = title, severity = Severity.HIGH, source = FindingSource.NETWORK,
        scope = "192.168.1.0/24", target = "$ip:$port", details = "d", remediation = "r", createdAt = created
    )

    @Test
    fun keyIsStableAcrossRunsButDiffersByIssue() {
        val a = netFinding("192.168.1.5", 22, "SSH open")
        val b = netFinding("192.168.1.5", 22, "SSH open", created = 999) // same issue, later run
        val c = netFinding("192.168.1.5", 23, "Telnet open")
        assertEquals(a.key, b.key)
        assertFalse(a.key == c.key)
    }

    @Test
    fun hostIpParsing() {
        assertEquals("192.168.1.5", netFinding("192.168.1.5", 22, "x").hostIp)
        val web = Finding(title = "t", severity = Severity.LOW, source = FindingSource.WEB,
            scope = "example.com", target = "example.com", details = "d", remediation = "r")
        assertEquals(null, web.hostIp)
    }

    @Test
    fun replaceHostOnlyAffectsThatHost() {
        val existing = listOf(
            netFinding("192.168.1.5", 22, "old ssh"),
            netFinding("192.168.1.9", 80, "other host"),
        )
        val fresh = listOf(netFinding("192.168.1.5", 23, "new telnet", created = 100))
        val merged = FindingMerge.replaceHost(existing, FindingSource.NETWORK, "192.168.1.0/24", "192.168.1.5", fresh, 100)
        val titles = merged.map { it.title }
        assertFalse(titles.contains("old ssh"))      // the host's old findings are gone
        assertTrue(titles.contains("other host"))    // other hosts untouched
        assertTrue(titles.contains("new telnet"))
    }

    @Test
    fun visibleHidesResolvedUnlessRequested() {
        val fixed = netFinding("192.168.1.5", 22, "patched")
        val open = netFinding("192.168.1.5", 23, "still open")
        val annotations = mapOf(
            fixed.key to FindingAnnotation(FindingStatus.FIXED),
            open.key to FindingAnnotation(FindingStatus.VERIFIED)
        )
        val all = listOf(fixed, open)
        assertEquals(listOf("still open"), FindingMerge.visible(all, annotations).map { it.title })
        assertEquals(2, FindingMerge.visible(all, annotations, includeResolved = true).size)
    }

    @Test
    fun statusParsingIsLenient() {
        assertEquals(FindingStatus.FIXED, FindingStatus.parse("FIXED"))
        assertEquals(FindingStatus.NEW, FindingStatus.parse(null))
        assertEquals(FindingStatus.NEW, FindingStatus.parse("bogus"))
    }

    @Test
    fun annotationDefaultDetection() {
        assertTrue(FindingAnnotation().isDefault)
        assertFalse(FindingAnnotation(FindingStatus.VERIFIED).isDefault)
        assertFalse(FindingAnnotation(notes = "check this").isDefault)
    }
}
