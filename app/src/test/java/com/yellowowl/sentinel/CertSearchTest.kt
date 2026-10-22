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
}
