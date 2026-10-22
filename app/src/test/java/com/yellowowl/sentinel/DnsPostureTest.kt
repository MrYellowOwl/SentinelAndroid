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

    @Test fun spfLookupCountCountsLookupMechanisms() {
        assertEquals(0, DnsPosture.spfLookupCount("v=spf1 ip4:1.2.3.4 -all"))
        assertEquals(3, DnsPosture.spfLookupCount("v=spf1 include:a.com include:b.com mx -all"))
        assertEquals(2, DnsPosture.spfLookupCount("v=spf1 a:mail.x.com redirect=_spf.y.com"))
    }

    @Test fun dmarcTagParsing() {
        val d = "v=DMARC1; p=reject; pct=50; rua=mailto:a@b.com"
        assertEquals("50", DnsPosture.dmarcTag(d, "pct"))
        assertEquals("mailto:a@b.com", DnsPosture.dmarcTag(d, "rua"))
        assertNull(DnsPosture.dmarcTag(d, "sp"))
    }

    @Test fun multipleSpfRecordsFlagged() {
        val r = DnsPosture.DnsRecords("example.com", spf = "v=spf1 -all", allSpf = listOf("v=spf1 -all", "v=spf1 include:x -all"), dmarc = "v=DMARC1; p=reject; rua=mailto:a@b.com", dkimFound = true, caaPresent = true, dnssecPresent = true)
        assertTrue(DnsPosture.findings("example.com", r).any { it.title == "Multiple SPF records" && it.severity == Severity.MEDIUM })
    }

    @Test fun spfOverLookupLimitFlagged() {
        val many = "v=spf1 " + (1..11).joinToString(" ") { "include:s$it.com" } + " -all"
        val r = DnsPosture.DnsRecords("example.com", spf = many, allSpf = listOf(many), dmarc = "v=DMARC1; p=reject; rua=mailto:a@b.com", dkimFound = true, caaPresent = true, dnssecPresent = true)
        assertTrue(DnsPosture.findings("example.com", r).any { it.title.contains("10 DNS-lookup limit") && it.severity == Severity.MEDIUM })
    }

    @Test fun dmarcPctAndMissingRuaFlagged() {
        val r = DnsPosture.DnsRecords("example.com", spf = "v=spf1 -all", allSpf = listOf("v=spf1 -all"), dmarc = "v=DMARC1; p=quarantine; pct=25", dkimFound = true, caaPresent = true, dnssecPresent = true)
        val fs = DnsPosture.findings("example.com", r)
        assertTrue(fs.any { it.title.contains("partially enforced") && it.severity == Severity.LOW })
        assertTrue(fs.any { it.title.contains("no aggregate reporting") && it.severity == Severity.LOW })
    }

    @Test fun missingCaaAndDnssecAreLow() {
        val r = DnsPosture.DnsRecords("example.com", spf = "v=spf1 -all", dmarc = "v=DMARC1; p=reject", dkimFound = true)
        val fs = DnsPosture.findings("example.com", r)
        assertTrue(fs.any { it.title == "No CAA record" && it.severity == Severity.LOW })
        assertTrue(fs.any { it.title == "DNSSEC not enabled" && it.severity == Severity.LOW })
    }
}
