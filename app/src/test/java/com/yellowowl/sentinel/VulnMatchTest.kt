package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class VulnMatchTest {
    private fun v(s: String) = SoftwareVersion.parse(s)!!

    @Test
    fun versionComparison() {
        assertTrue(v("2.4.49") > v("2.4.41"))
        assertTrue(v("2.4.41") < v("2.4.49"))
        assertTrue(v("8.3") > v("8.2p1"))
        assertTrue(v("1.18.0") > v("1.9.0"))      // numeric, not lexical
        assertTrue(v("10.3.25") > v("9.9.99"))
        assertEquals(0, v("2.4.41").compareTo(v("2.4.41")))
        assertTrue(v("2.4.41") > v("2.4"))         // missing component treated as 0
    }

    @Test
    fun versionParsingHandlesSuffixes() {
        assertEquals("8.2.p.1", v("8.2p1").toString())
        assertEquals("10.3.25.mariadb", v("10.3.25-MariaDB").toString())
        assertEquals(null, SoftwareVersion.parse("   "))
    }

    @Test
    fun rangeFixedInIsExclusiveUpperBound() {
        val range = VersionRange(fixed = "2.4.49")
        assertTrue(range.contains(v("2.4.41")))
        assertFalse(range.contains(v("2.4.49")))   // the fixed version is not affected
        assertFalse(range.contains(v("2.4.50")))
    }

    @Test
    fun rangeWithBothBounds() {
        val range = VersionRange(introduced = "7.0", fixed = "8.3")
        assertFalse(range.contains(v("6.9")))
        assertTrue(range.contains(v("7.0")))        // inclusive lower
        assertTrue(range.contains(v("8.2p1")))
        assertFalse(range.contains(v("8.3")))
    }

    @Test
    fun exactVersionList() {
        val range = VersionRange(exact = listOf("1.2.3", "1.2.5"))
        assertTrue(range.contains(v("1.2.3")))
        assertFalse(range.contains(v("1.2.4")))
    }

    @Test
    fun severityMappingAndExploitBump() {
        assertEquals(Severity.HIGH, KnownVuln.severityOf(9.8, false))
        assertEquals(Severity.MEDIUM, KnownVuln.severityOf(5.3, false))
        assertEquals(Severity.LOW, KnownVuln.severityOf(2.1, false))
        // A public exploit raises a medium to high priority.
        assertEquals(Severity.HIGH, KnownVuln.severityOf(5.3, true))
        assertEquals(Severity.MEDIUM, KnownVuln.severityOf(null, false))
    }

    private val db = listOf(
        KnownVuln("CVE-A", "openssh", VersionRange(fixed = "8.3"), cvss = 7.5, summary = "Flaw in OpenSSH.", exploitAvailable = false),
        KnownVuln("CVE-B", "openssh", VersionRange(introduced = "8.0", fixed = "8.5"), cvss = 5.0, summary = "Lesser flaw.", exploitAvailable = true),
        KnownVuln("CVE-C", "apache_httpd", VersionRange(fixed = "2.4.49"), cvss = 9.8, summary = "RCE.", exploitAvailable = true),
        KnownVuln("CVE-OLD", "openssh", VersionRange(fixed = "7.0"), cvss = 10.0, summary = "Old.", exploitAvailable = true)
    )
    private val matcher = VulnMatcher(db)

    @Test
    fun matcherFindsAffectedAndSkipsPatched() {
        val hits = matcher.match(ServiceFingerprint("OpenSSH", "8.2p1"))
        // CVE-OLD excluded (fixed < 7.0). Both remaining are HIGH, so the one with a public exploit sorts first.
        assertEquals(listOf("CVE-B", "CVE-A"), hits.map { it.id })
        assertEquals(Severity.HIGH, hits[0].severity)
        assertTrue(hits[0].exploitAvailable)
    }

    @Test
    fun matcherNormalizesProductAliases() {
        // Fingerprint "Apache httpd" → key "apache_httpd"; also matches an "apache" entry via alias.
        val hits = matcher.match(ServiceFingerprint("Apache httpd", "2.4.41"))
        assertEquals(listOf("CVE-C"), hits.map { it.id })
    }

    @Test
    fun matcherNeedsAVersion() {
        assertTrue(matcher.match(ServiceFingerprint("OpenSSH", null)).isEmpty())
    }

    @Test
    fun findingsForDeviceCarryTargetAndFix() {
        val device = DeviceResult(
            ipAddress = "192.168.1.10",
            openPorts = listOf(PortFinding(22, "SSH", ServiceFingerprint("OpenSSH", "8.2p1")))
        )
        val findings = matcher.findingsFor("192.168.1.0/24", device)
        assertEquals(2, findings.size)
        val top = findings.first { it.title.startsWith("CVE-A") }
        assertEquals("192.168.1.10:22", top.target)
        assertTrue(top.remediation.contains("Upgrade OpenSSH to 8.3"))
        assertTrue(findings.first { it.title.startsWith("CVE-B") }.details.contains("public exploit"))
    }
}
