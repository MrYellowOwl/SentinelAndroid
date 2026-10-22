package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ComplianceTest {
    private fun f(title: String, details: String = "") =
        Finding(title = title, severity = Severity.MEDIUM, source = FindingSource.WEB, scope = "s", target = "t", details = details, remediation = "")

    @Test fun mapsCveToVulnComponents() {
        val t = Compliance.tag(f("CVE-2021-41773 in Apache"))
        assertEquals("A06: Vulnerable & Outdated Components", t.owasp)
        assertTrue(t.cis!!.contains("Vulnerability Management"))
    }

    @Test fun mapsTlsToCrypto() {
        assertEquals("A02: Cryptographic Failures", Compliance.tag(f("Obsolete TLS protocol enabled")).owasp)
        assertEquals("A02: Cryptographic Failures", Compliance.tag(f("HSTS not enabled")).owasp)
    }

    @Test fun mapsEmailAndHeaders() {
        assertEquals("A05: Security Misconfiguration", Compliance.tag(f("No DMARC record")).owasp)
        assertEquals("A05: Security Misconfiguration", Compliance.tag(f("Cookies without SameSite protection")).owasp)
    }

    @Test fun mapsExposedPaths() {
        assertEquals("A01: Broken Access Control", Compliance.tag(f("Exposed: /.git/config")).owasp)
    }

    @Test fun unmatchedIsEmpty() {
        val t = Compliance.tag(f("Baseline checks passed"))
        assertNull(t.owasp)
        assertTrue(t.labels.isEmpty())
    }
}
