package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsPostureTest {
    @Test fun parsesSpfQualifier() {
        assertEquals('-', DnsPosture.spfAllQualifier("v=spf1 include:_spf.google.com -all"))
        assertEquals('~', DnsPosture.spfAllQualifier("v=spf1 ~all"))
        assertEquals('+', DnsPosture.spfAllQualifier("v=spf1 +all"))
        assertEquals('?', DnsPosture.spfAllQualifier("v=spf1 ?all"))
        assertNull(DnsPosture.spfAllQualifier("v=spf1 include:x.com"))
        assertNull(DnsPosture.spfAllQualifier(null))
    }

    @Test fun parsesDmarcPolicy() {
        assertEquals("reject", DnsPosture.dmarcPolicy("v=DMARC1; p=reject; rua=mailto:a@b.com"))
        assertEquals("none", DnsPosture.dmarcPolicy("v=DMARC1;p=none"))
        assertEquals("quarantine", DnsPosture.dmarcPolicy("v=DMARC1; p = quarantine"))
        assertNull(DnsPosture.dmarcPolicy(null))
    }

    @Test fun missingSpfAndDmarcWithMxAreMedium() {
        val r = DnsPosture.DnsRecords("example.com", spf = null, dmarc = null, hasMx = true)
        val fs = DnsPosture.findings("example.com", r)
        assertTrue(fs.any { it.title == "No SPF record" && it.severity == Severity.MEDIUM })
        assertTrue(fs.any { it.title == "No DMARC record" && it.severity == Severity.MEDIUM })
    }

    @Test fun plusAllIsHighAndMonitorOnlyIsLow() {
        val r = DnsPosture.DnsRecords("example.com", spf = "v=spf1 +all", dmarc = "v=DMARC1; p=none", hasMx = true)
        val fs = DnsPosture.findings("example.com", r)
        assertTrue(fs.any { it.title.contains("+all") && it.severity == Severity.HIGH })
        assertTrue(fs.any { it.title.contains("monitor-only") && it.severity == Severity.LOW })
    }

    @Test fun strongConfigIsInfoOnlyPlusRecommendations() {
        val r = DnsPosture.DnsRecords("example.com", spf = "v=spf1 -all", dmarc = "v=DMARC1; p=reject",
            dkimFound = true, caaPresent = true, dnssecPresent = true, hasMx = true)
        val fs = DnsPosture.findings("example.com", r)
        // No MEDIUM/HIGH when everything is in place.
        assertTrue(fs.none { it.severity == Severity.MEDIUM || it.severity == Severity.HIGH })
        assertTrue(fs.any { it.title.contains("posture summary") })
    }

    @Test fun missingCaaAndDnssecAreLow() {
        val r = DnsPosture.DnsRecords("example.com", spf = "v=spf1 -all", dmarc = "v=DMARC1; p=reject", dkimFound = true)
        val fs = DnsPosture.findings("example.com", r)
        assertTrue(fs.any { it.title == "No CAA record" && it.severity == Severity.LOW })
        assertTrue(fs.any { it.title == "DNSSEC not enabled" && it.severity == Severity.LOW })
    }
}
