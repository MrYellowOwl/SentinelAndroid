package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ExternalIntelTest {
    @Test fun parsesShodanHost() {
        val json = """{"ip_str":"1.2.3.4","ports":[443,22,80],"hostnames":["a.example.com"],
            "org":"Acme","os":"Linux","vulns":["CVE-2021-41773"]}"""
        val i = ExternalIntel.parseShodan(json)!!
        assertEquals(listOf(22, 80, 443), i.ports)
        assertEquals("Acme", i.org)
        assertEquals(listOf("CVE-2021-41773"), i.vulns)
    }

    @Test fun shodanErrorIsNull() {
        assertNull(ExternalIntel.parseShodan("""{"error":"No information available"}"""))
        assertNull(ExternalIntel.parseShodan("junk"))
    }

    @Test fun shodanVulnsBecomeMediumFinding() {
        val i = ExternalIntel.ShodanInfo("1.2.3.4", listOf(443), emptyList(), "Acme", "Linux", listOf("CVE-2021-41773"))
        val fs = ExternalIntel.shodanFindings("s", "1.2.3.4", i)
        assertTrue(fs.any { it.severity == Severity.INFO })        // exposure summary
        assertTrue(fs.any { it.severity == Severity.MEDIUM && it.title.contains("known CVEs") })
    }

    @Test fun parsesVirusTotalStats() {
        val json = """{"data":{"attributes":{"reputation":-5,"last_analysis_stats":{"malicious":4,"suspicious":1,"harmless":60,"undetected":3}}}}"""
        val v = ExternalIntel.parseVirusTotal(json)!!
        assertEquals(4, v.malicious)
        assertEquals(1, v.suspicious)
        assertEquals(-5, v.reputation)
    }

    @Test fun vtSeverityScalesWithDetections() {
        assertEquals(Severity.HIGH, ExternalIntel.vtFinding("s", "t", ExternalIntel.VtInfo(4, 0, 50, 0)).severity)
        assertEquals(Severity.MEDIUM, ExternalIntel.vtFinding("s", "t", ExternalIntel.VtInfo(1, 1, 50, 0)).severity)
        assertEquals(Severity.INFO, ExternalIntel.vtFinding("s", "t", ExternalIntel.VtInfo(0, 0, 60, 0)).severity)
    }

    @Test fun vtMissingStatsIsNull() {
        assertNull(ExternalIntel.parseVirusTotal("""{"data":{"attributes":{}}}"""))
    }
}
