package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CertSearchTest {
    @Test fun buildsCrtShUrl() {
        assertEquals("https://crt.sh/?q=%25.example.com&output=json", CertSearch.crtShUrl("Example.com"))
    }

    @Test fun parsesDedupesAndFiltersToDomain() {
        val json = """[
            {"name_value":"www.example.com\n*.example.com","common_name":"example.com"},
            {"name_value":"api.example.com","common_name":"api.example.com"},
            {"name_value":"www.example.com","common_name":"www.example.com"},
            {"name_value":"mail.other.com","common_name":"other.com"}
        ]"""
        val subs = CertSearch.parseSubdomains(json, "example.com")
        assertTrue(subs.contains("example.com"))
        assertTrue(subs.contains("www.example.com"))
        assertTrue(subs.contains("api.example.com"))
        assertFalse(subs.contains("mail.other.com"))      // different domain excluded
        assertFalse(subs.any { it.startsWith("*.") })      // wildcard normalized
        assertEquals(subs.distinct(), subs)                // deduped
        assertEquals("example.com", subs.first())          // apex sorts first (fewest dots)
    }

    @Test fun junkReturnsEmpty() {
        assertTrue(CertSearch.parseSubdomains("not json", "example.com").isEmpty())
    }

    @Test fun salvagesTruncatedCrtShArray() {
        // A large crt.sh response capped mid-stream: the array never closes, so JSON parsing fails,
        // but the complete records before the cut should still be recovered.
        val truncated = """[
            {"name_value":"www.example.com\nassets.example.com","common_name":"example.com"},
            {"name_value":"api.example.com","common_name":"api.example.com"},
            {"name_value":"cut.example.c""".trimIndent()
        val subs = CertSearch.parseSubdomains(truncated, "example.com")
        assertTrue(subs.contains("www.example.com"))
        assertTrue(subs.contains("assets.example.com"))
        assertTrue(subs.contains("api.example.com"))
        assertFalse(subs.any { it.startsWith("*.") })
    }

    @Test fun buildsCertSpotterUrl() {
        assertEquals(
            "https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names",
            CertSearch.certSpotterUrl("Example.com")
        )
    }

    @Test fun sortHostsDedupesAndOrdersByDepth() {
        val merged = CertSearch.sortHosts(
            listOf("api.example.com", "example.com", "www.example.com", "example.com", "a.b.example.com")
        )
        assertEquals(listOf("example.com", "api.example.com", "www.example.com", "a.b.example.com"), merged)
    }

    @Test fun flagsSubdomainsResolvingToPrivateIps() {
        assertTrue(CertSearch.hasInternalAddress(listOf("10.0.0.5")))
        assertTrue(CertSearch.hasInternalAddress(listOf("93.184.216.34", "192.168.1.10")))
        assertFalse(CertSearch.hasInternalAddress(listOf("93.184.216.34")))
        assertFalse(CertSearch.hasInternalAddress(emptyList()))
    }

    @Test fun describesResolvedSubdomains() {
        assertEquals("www.example.com → 93.184.216.34",
            CertSearch.describeResolved("www.example.com", listOf("93.184.216.34")))
        assertEquals("admin.example.com → 10.0.0.5  [INTERNAL]",
            CertSearch.describeResolved("admin.example.com", listOf("10.0.0.5")))
        assertEquals("stale.example.com",   // no A record -> name only
            CertSearch.describeResolved("stale.example.com", emptyList()))
    }

    @Test fun parsesCertSpotterDnsNames() {
        val json = """[
            {"dns_names":["example.com","www.example.com","*.example.com"]},
            {"dns_names":["vpn.example.com","mail.other.com"]}
        ]"""
        val subs = CertSearch.parseCertSpotter(json, "example.com")
        assertTrue(subs.contains("example.com"))
        assertTrue(subs.contains("www.example.com"))
        assertTrue(subs.contains("vpn.example.com"))
        assertFalse(subs.contains("mail.other.com"))      // other domain filtered out
        assertFalse(subs.any { it.startsWith("*.") })      // wildcard normalized
    }
}
