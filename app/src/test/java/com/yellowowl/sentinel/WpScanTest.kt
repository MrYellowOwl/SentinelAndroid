package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class WpScanTest {
    @Test
    fun detectsWordPressAndVersionAndAssets() {
        val html = """
            <html><head>
            <meta name="generator" content="WordPress 6.4.2" />
            <link rel="stylesheet" href="https://site.com/wp-content/themes/divi/style.css?ver=4.23" />
            <script src="/wp-content/plugins/contact-form-7/includes/js/index.js?ver=5.8.1"></script>
            <script src="/wp-content/plugins/woocommerce/assets/js/frontend.js?ver=8.3.0"></script>
            </head><body>hi</body></html>
        """.trimIndent()
        val s = WpScan.detect(html, emptyMap())
        assertTrue(s.isWordPress)
        assertEquals("6.4.2", s.version)
        assertEquals(listOf("contact-form-7", "woocommerce"), s.plugins.map { it.slug })
        assertEquals("5.8.1", s.plugins.first { it.slug == "contact-form-7" }.version)
        assertEquals("divi", s.themes.single().slug)
        assertEquals("4.23", s.themes.single().version)
    }

    @Test
    fun detectsViaLinkHeaderWhenHtmlIsBare() {
        val headers = mapOf("link" to listOf("<https://site.com/wp-json/>; rel=\"https://api.w.org/\""))
        assertTrue(WpScan.detect("<html></html>", headers).isWordPress)
    }

    @Test
    fun nonWordPressSiteIsNotFlagged() {
        assertFalse(WpScan.detect("<html><body>Just a site</body></html>", emptyMap()).isWordPress)
    }

    @Test
    fun parsesRestUsers() {
        val json = """[{"id":1,"name":"Site Admin","slug":"admin"},{"id":2,"name":"Jane","slug":"jane"}]"""
        val users = WpScan.parseUsers(json)
        assertEquals(2, users.size)
        assertEquals("admin", users[0].slug)
        assertEquals("Jane", users[1].name)
        assertTrue(WpScan.parseUsers("not json").isEmpty())
    }

    @Test
    fun authorSlugFromRedirect() {
        assertEquals("admin", WpScan.authorSlug("https://site.com/author/admin/"))
        assertNull(WpScan.authorSlug("https://site.com/?author=1"))
        assertNull(WpScan.authorSlug(null))
    }

    @Test
    fun xmlrpcDetection() {
        assertTrue(WpScan.xmlrpcEnabled(405, ""))
        assertTrue(WpScan.xmlrpcEnabled(200, "XML-RPC server accepts POST requests only."))
        assertFalse(WpScan.xmlrpcEnabled(404, "Not found"))
    }

    @Test
    fun versionFromReadme() {
        assertEquals("6.1.1", WpScan.versionFromReadme("<h1>WordPress</h1>\n<br />\nVersion 6.1.1"))
    }

    @Test
    fun userFindingMentionsBothSources() {
        val f = WpScan.userFindings("site.com", "site.com",
            listOf(WpUser(1, "Admin", "admin")), authorSlug = "editor").single()
        assertEquals(Severity.MEDIUM, f.severity)
        assertTrue(f.details.contains("REST API"))
        assertTrue(f.details.contains("author archives"))
        assertTrue(f.details.contains("admin") && f.details.contains("editor"))
    }

    @Test
    fun noUsersMeansNoFinding() {
        assertTrue(WpScan.userFindings("s", "s", emptyList(), null).isEmpty())
    }

    @Test
    fun exposureSeveritiesByPath() {
        assertEquals(Severity.HIGH, WpScan.exposureFinding("s", "h", "/wp-config.php.bak").severity)
        assertEquals(Severity.HIGH, WpScan.exposureFinding("s", "h", "/.git/config").severity)
        assertEquals(Severity.MEDIUM, WpScan.exposureFinding("s", "h", "/wp-content/debug.log").severity)
        assertEquals(Severity.LOW, WpScan.exposureFinding("s", "h", "/wp-content/uploads/").severity)
    }

    @Test
    fun pluginVersionsRunThroughCveMatcher() {
        val matcher = VulnMatcher(listOf(
            KnownVuln("CVE-WP-1", "contact-form-7", VersionRange(fixed = "5.8.2"), cvss = 8.8, summary = "Flaw.", exploitAvailable = true)
        ))
        val signals = WpSignals(true, plugins = listOf(WpAsset("contact-form-7", "5.8.1")))
        val findings = WpScan.assetCveFindings("site.com", "site.com", signals, matcher)
        assertEquals(1, findings.size)
        assertTrue(findings[0].title.startsWith("CVE-WP-1"))
        assertEquals(Severity.HIGH, findings[0].severity)
    }

    @Test
    fun inventoryFindingListsComponents() {
        val signals = WpSignals(true,
            plugins = listOf(WpAsset("woocommerce", "8.3.0")),
            themes = listOf(WpAsset("divi", "4.23")))
        val f = WpScan.inventoryFinding("s", "h", signals)!!
        assertEquals(Severity.INFO, f.severity)
        assertTrue(f.details.contains("woocommerce 8.3.0"))
        assertTrue(f.details.contains("divi 4.23"))
        assertNull(WpScan.inventoryFinding("s", "h", WpSignals(true)))
    }
}

class Php2ShellTest {
    // PHP2Shell CVE entries as shipped in the seed (per-branch fixed versions).
    private val php2shell = listOf(
        KnownVuln("CVE-2026-109618/9", "php", VersionRange("8.5.0", "8.5.12"), 9.2, exploitAvailable = true, fixText = "Upgrade to 8.5.12+"),
        KnownVuln("CVE-2026-109618/9", "php", VersionRange("8.4.0", "8.4.27"), 9.2, exploitAvailable = true, fixText = "Upgrade to 8.4.27+"),
        KnownVuln("CVE-2026-109618/9", "php", VersionRange("8.3.0", "8.3.36"), 9.2, exploitAvailable = true, fixText = "Upgrade to 8.3.36+"),
        KnownVuln("CVE-2026-109618/9", "php", VersionRange("8.2.0", "8.2.35"), 9.2, exploitAvailable = true, fixText = "Upgrade to 8.2.35+"),
        KnownVuln("CVE-2026-109618/9", "php", VersionRange("5.4.0", "8.2.0"), 9.2, exploitAvailable = true, fixText = "EOL; upgrade to a supported branch")
    )
    private val matcher = VulnMatcher(php2shell)

    @org.junit.Test
    fun vulnerablePhpVersionsAreFlagged() {
        org.junit.Assert.assertEquals(1, matcher.match(ServiceFingerprint("php", "8.3.35")).size)
        org.junit.Assert.assertEquals(1, matcher.match(ServiceFingerprint("php", "8.4.26")).size)
        org.junit.Assert.assertEquals(1, matcher.match(ServiceFingerprint("php", "8.2.34")).size)
        org.junit.Assert.assertEquals(1, matcher.match(ServiceFingerprint("php", "7.4.33")).size) // EOL range
        val hit = matcher.match(ServiceFingerprint("php", "8.3.35")).first()
        org.junit.Assert.assertEquals(Severity.HIGH, hit.severity)
        org.junit.Assert.assertTrue(hit.toFinding("s", "1.2.3.4", 443, ServiceFingerprint("php", "8.3.35")).remediation.contains("8.3.36"))
    }

    @org.junit.Test
    fun patchedPhpVersionsAreNotFlagged() {
        org.junit.Assert.assertTrue(matcher.match(ServiceFingerprint("php", "8.3.36")).isEmpty())
        org.junit.Assert.assertTrue(matcher.match(ServiceFingerprint("php", "8.4.27")).isEmpty())
        org.junit.Assert.assertTrue(matcher.match(ServiceFingerprint("php", "8.2.35")).isEmpty())
        org.junit.Assert.assertTrue(matcher.match(ServiceFingerprint("php", "8.5.12")).isEmpty())
    }

    @org.junit.Test
    fun phpVersionExtractionFromHeaders() {
        org.junit.Assert.assertEquals("8.3.35", WebChecks.phpVersion(mapOf("x-powered-by" to listOf("PHP/8.3.35"))))
        org.junit.Assert.assertEquals("8.2.34", WebChecks.phpVersion(mapOf("server" to listOf("Apache/2.4.58 (Ubuntu) PHP/8.2.34"))))
        org.junit.Assert.assertNull(WebChecks.phpVersion(mapOf("server" to listOf("nginx"))))
    }

    @org.junit.Test
    fun phpHiddenDetection() {
        org.junit.Assert.assertTrue(WebChecks.phpDetectedWithoutVersion(mapOf("set-cookie" to listOf("PHPSESSID=abc; path=/"))))
        org.junit.Assert.assertTrue(WebChecks.phpDetectedWithoutVersion(mapOf("x-powered-by" to listOf("PHP"))))
        org.junit.Assert.assertFalse(WebChecks.phpDetectedWithoutVersion(mapOf("x-powered-by" to listOf("PHP/8.3.35"))))
        org.junit.Assert.assertFalse(WebChecks.phpDetectedWithoutVersion(mapOf("server" to listOf("nginx"))))
    }
}
