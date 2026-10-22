package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KevEpssTest {
    @Test fun kevBumpsSeverityToHighEvenAtMidCvss() {
        val v = KnownVuln("CVE-2020-0001", "nginx", VersionRange(fixed = "1.20.0"), cvss = 5.0, kev = true)
        assertEquals(Severity.HIGH, v.severity)
    }

    @Test fun kevFindingIsLabelledAndExplained() {
        val v = KnownVuln("CVE-2020-0001", "nginx", VersionRange(fixed = "1.20.0"), cvss = 5.0, kev = true, epss = 0.73)
        val f = v.toFinding("s", "1.2.3.4", 443, ServiceFingerprint("nginx", "1.18.0"))
        assertTrue(f.title.startsWith("[KEV]"))
        assertTrue(f.details.contains("Known Exploited"))
        assertTrue(f.details.contains("EPSS 73%"))
    }

    @Test fun matcherRanksKevAboveNonKevAtSameSeverity() {
        val matcher = VulnMatcher(listOf(
            KnownVuln("CVE-A", "nginx", VersionRange(fixed = "1.20.0"), cvss = 9.0, kev = false),
            KnownVuln("CVE-B", "nginx", VersionRange(fixed = "1.20.0"), cvss = 9.0, kev = true)
        ))
        val ranked = matcher.match(ServiceFingerprint("nginx", "1.18.0"))
        assertEquals("CVE-B", ranked.first().id)   // KEV wins the tie
    }

    @Test fun epssBreaksTiesWhenNoKev() {
        val matcher = VulnMatcher(listOf(
            KnownVuln("CVE-LOWP", "nginx", VersionRange(fixed = "1.20.0"), cvss = 9.0, epss = 0.1),
            KnownVuln("CVE-HIGHP", "nginx", VersionRange(fixed = "1.20.0"), cvss = 9.0, epss = 0.9)
        ))
        val ranked = matcher.match(ServiceFingerprint("nginx", "1.18.0"))
        assertEquals("CVE-HIGHP", ranked.first().id)
    }
}
