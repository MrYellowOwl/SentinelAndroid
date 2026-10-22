package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ScopeTest {
    @Test fun parsesMixedSeparators() {
        val e = Scope.parse("192.168.1.0/24, example.com\n10.0.0.5 acme.io")
        assertEquals(4, e.size)
    }

    @Test fun emptyScopeMeansEverythingInScope() {
        assertTrue(Scope.inScope(emptyList(), "anything.com"))
        assertTrue(Scope.outOfScope(emptyList(), listOf("a", "b")).isEmpty())
    }

    @Test fun cidrMatching() {
        val e = Scope.parse("192.168.1.0/24")
        assertTrue(Scope.inScope(e, "192.168.1.55"))
        assertTrue(Scope.inScope(e, "192.168.1.55:443"))
        assertFalse(Scope.inScope(e, "192.168.2.10"))
        assertTrue(Scope.inScope(Scope.parse("10.0.0.0/8"), "10.4.5.6"))
    }

    @Test fun domainAndSubdomainMatching() {
        val e = Scope.parse("example.com")
        assertTrue(Scope.inScope(e, "example.com"))
        assertTrue(Scope.inScope(e, "https://www.example.com/path"))
        assertTrue(Scope.inScope(e, "api.example.com"))
        assertFalse(Scope.inScope(e, "notexample.com"))
        assertFalse(Scope.inScope(e, "example.com.evil.net"))
    }

    @Test fun wildcardDomainEntry() {
        assertTrue(Scope.inScope(Scope.parse("*.acme.io"), "mail.acme.io"))
    }

    @Test fun outOfScopeListing() {
        val e = Scope.parse("192.168.1.0/24, example.com")
        val out = Scope.outOfScope(e, listOf("192.168.1.5", "8.8.8.8", "example.com", "evil.net"))
        assertEquals(listOf("8.8.8.8", "evil.net"), out)
    }
}
