package com.yellowowl.sentinel

import java.net.URL
import java.net.UnknownHostException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateExpiredException
import javax.net.ssl.SSLHandshakeException
import javax.net.ssl.SSLPeerUnverifiedException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

@Suppress("DEPRECATION")
class WebChecksTest {
    private val day = 24L * 60 * 60 * 1000

    private fun response(url: String, code: Int = 200, vararg headers: Pair<String, String>) = HttpResponseInfo(
        URL(url), code,
        headers.groupBy({ it.first.lowercase() }, { it.second })
    )

    private fun titles(findings: List<Finding>) = findings.map { it.title }

    @Test
    fun bareDomainDefaultsToHttps() {
        assertEquals("https://example.com", WebChecks.normalizeUrl("  example.com ").toString())
        assertEquals("http://example.com/path?q=1", WebChecks.normalizeUrl("http://example.com/path?q=1").toString())
    }

    @Test
    fun invalidAddressesAreRejectedWithFriendlyMessages() {
        listOf("", "ftp://example.com", "https://user:pw@example.com", "exa mple.com", "https://").forEach { input ->
            try {
                WebChecks.normalizeUrl(input)
                fail("expected rejection for '$input'")
            } catch (e: IllegalArgumentException) {
                assertNotNull(e.message)
            }
        }
    }

    @Test
    fun redirectsResolveRelativeAndRejectOtherSchemes() {
        val base = URL("https://example.com/a/b")
        assertEquals("https://example.com/login", WebChecks.resolveRedirect(base, "/login").toString())
        assertEquals("http://other.org/", WebChecks.resolveRedirect(base, "http://other.org/").toString())
        assertNull(WebChecks.resolveRedirect(base, "javascript:alert(1)"))
        assertNull(WebChecks.resolveRedirect(base, null))
        assertTrue(WebChecks.isRedirect(301))
        assertTrue(WebChecks.isRedirect(308))
        assertFalse(WebChecks.isRedirect(304))
        assertFalse(WebChecks.isRedirect(200))
    }

    @Test
    fun headerNamesAreMergedCaseInsensitively() {
        val merged = WebChecks.normalizeHeaders(
            mapOf(null to listOf("HTTP/1.1 200 OK"), "Set-Cookie" to listOf("a=1"), "set-cookie" to listOf("b=2"))
        )
        assertEquals(listOf("a=1", "b=2"), merged["set-cookie"])
        assertEquals(1, merged.size)
    }

    @Test
    fun missingHeadersOnHttpsAreReported() {
        val findings = WebChecks.analyzeResponse("example.com", response("https://example.com/"))
        val byTitle = findings.associateBy { it.title }
        assertEquals(Severity.MEDIUM, byTitle["HSTS not enabled"]?.severity)
        assertEquals(Severity.MEDIUM, byTitle["Content Security Policy not set"]?.severity)
        assertEquals(Severity.LOW, byTitle["X-Content-Type-Options not set"]?.severity)
        assertEquals(Severity.LOW, byTitle["Clickjacking protection not set"]?.severity)
        assertEquals(Severity.INFO, byTitle["Referrer-Policy not set"]?.severity)
    }

    @Test
    fun wellConfiguredSiteHasNoIssues() {
        val findings = WebChecks.analyzeResponse(
            "example.com",
            response(
                "https://example.com/", 200,
                "Strict-Transport-Security" to "max-age=31536000; includeSubDomains",
                "Content-Security-Policy" to "default-src 'self'; frame-ancestors 'self'",
                "X-Content-Type-Options" to "nosniff",
                "Referrer-Policy" to "strict-origin-when-cross-origin",
                "Server" to "nginx",
                "Set-Cookie" to "sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax"
            )
        )
        assertTrue(titles(findings).toString(), findings.isEmpty())
    }

    @Test
    fun shortHstsAndInsecureCookiesAreFlagged() {
        val findings = WebChecks.analyzeResponse(
            "example.com",
            response(
                "https://example.com/", 200,
                "Strict-Transport-Security" to "max-age=300",
                "Set-Cookie" to "sid=abc; Path=/; HttpOnly",
                "Set-Cookie" to "theme=dark; Secure",
                "X-Powered-By" to "PHP/8.1.2",
                "Server" to "Apache/2.4.41 (Ubuntu)"
            )
        )
        val t = titles(findings)
        assertTrue(t.contains("HSTS max-age is short"))
        val insecure = findings.first { it.title == "Cookies set without the Secure flag" }
        assertTrue(insecure.details.contains("sid"))
        assertFalse(insecure.details.contains("theme"))
        assertTrue(findings.first { it.title == "Cookies readable by JavaScript" }.details.contains("theme"))
        assertTrue(t.contains("Technology disclosed in X-Powered-By"))
        assertTrue(t.contains("Server version disclosed"))
    }

    @Test
    fun cspFrameAncestorsCountsAsClickjackingProtection() {
        val findings = WebChecks.analyzeResponse(
            "example.com",
            response("https://example.com/", 200, "Content-Security-Policy" to "frame-ancestors 'none'")
        )
        assertFalse(titles(findings).contains("Clickjacking protection not set"))
    }

    @Test
    fun hstsIsNotExpectedOnPlainHttp() {
        val findings = WebChecks.analyzeResponse("example.com", response("http://example.com/"))
        assertFalse(titles(findings).contains("HSTS not enabled"))
    }

    @Test
    fun transportScenarios() {
        val https = URL("https://example.com")
        val http = URL("http://example.com")

        // Typed http://, ended on https:// -> good.
        assertEquals("HTTP redirects to HTTPS", WebChecks.transportFindings("s", http, URL("https://example.com/"), null).single().title)

        // https -> http downgrade.
        assertEquals(Severity.HIGH, WebChecks.transportFindings("s", https, URL("http://example.com/"), null).single().severity)

        // https works; http counterpart redirects -> good.
        val redirects = CounterpartProbe.Reached(URL("https://example.com/"), 200)
        assertEquals("HTTP redirects to HTTPS", WebChecks.transportFindings("s", https, https, redirects).single().title)

        // https works; http counterpart serves content without redirect -> medium.
        val noRedirect = CounterpartProbe.Reached(URL("http://example.com/"), 200)
        assertEquals(Severity.MEDIUM, WebChecks.transportFindings("s", https, https, noRedirect).single().severity)

        // https works; nothing on port 80 -> info.
        assertEquals(Severity.INFO, WebChecks.transportFindings("s", https, https, CounterpartProbe.Unreachable).single().severity)

        // http only, no https -> high.
        assertEquals(Severity.HIGH, WebChecks.transportFindings("s", http, http, CounterpartProbe.Unreachable).single().severity)

        // http stays http, but https exists -> medium "not enforced".
        val httpsWorks = CounterpartProbe.Reached(URL("https://example.com/"), 200)
        assertEquals("HTTPS available but not enforced", WebChecks.transportFindings("s", http, http, httpsWorks).single().title)
    }

    @Test
    fun certificateExpiryBands() {
        val now = 1_700_000_000_000L
        assertEquals(Severity.HIGH, WebChecks.certificateFinding("s", "h", now - day, now).severity)
        assertEquals(Severity.HIGH, WebChecks.certificateFinding("s", "h", now + 10 * day, now).severity)
        assertEquals(Severity.MEDIUM, WebChecks.certificateFinding("s", "h", now + 20 * day, now).severity)
        assertEquals(Severity.INFO, WebChecks.certificateFinding("s", "h", now + 90 * day, now).severity)
    }

    @Test
    fun tlsFailuresAreClassified() {
        val expired = SSLHandshakeException("Chain validation failed").apply {
            initCause(CertPathValidatorException("validity check failed", CertificateExpiredException("NotAfter: ...")))
        }
        assertEquals("TLS certificate has expired", WebChecks.tlsFailureFinding("s", "example.com", expired)?.title)

        val untrusted = SSLHandshakeException("handshake failed").apply {
            initCause(CertPathValidatorException("Trust anchor for certification path not found."))
        }
        assertEquals("TLS certificate isn't trusted", WebChecks.tlsFailureFinding("s", "example.com", untrusted)?.title)

        val mismatch = SSLPeerUnverifiedException("Hostname example.com not verified")
        assertEquals("Certificate doesn't match the website name", WebChecks.tlsFailureFinding("s", "example.com", mismatch)?.title)

        assertNull(WebChecks.tlsFailureFinding("s", "example.com", UnknownHostException("example.com")))
    }

    @Test
    fun summaryAddedOnlyWhenNothingAboveInfo() {
        val info = WebChecks.certificateFinding("s", "h", System.currentTimeMillis() + 90 * day, System.currentTimeMillis())
        assertEquals("Baseline checks passed", WebChecks.withSummary("s", "h", listOf(info)).last().title)
        val withIssue = WebChecks.analyzeResponse("s", response("https://example.com/"))
        assertEquals(withIssue, WebChecks.withSummary("s", "h", withIssue))
    }

    @Test
    fun friendlyErrors() {
        assertTrue(WebChecks.friendlyError(UnknownHostException("x")).startsWith("Couldn't find that website"))
        assertEquals("custom", WebChecks.friendlyError(IllegalStateException("custom")))
        assertEquals("The website redirected too many times.", WebChecks.friendlyError(TooManyRedirectsException()))
    }
}
