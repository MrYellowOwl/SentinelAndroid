package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WebDevReportTest {
    @Test fun arpTableParsesCompleteEntriesOnly() {
        val text = """IP address       HW type     Flags       HW address            Mask     Device
10.0.0.1         0x1         0x2         aa:bb:cc:dd:ee:ff     *        wlan0
10.0.0.9         0x1         0x0         00:00:00:00:00:00     *        wlan0
10.0.0.5         0x1         0x2         11:22:33:44:55:66     *        wlan0"""
        val m = ArpTable.parse(text)
        assertEquals("aa:bb:cc:dd:ee:ff", m["10.0.0.1"])
        assertEquals("11:22:33:44:55:66", m["10.0.0.5"])
        assertFalse(m.containsKey("10.0.0.9"))   // incomplete (flags 0x0) skipped
        assertEquals(2, m.size)
    }

    private val profile = SiteProfile(
        input = "acme.com", domain = "acme.com", canonicalUrl = "https://www.acme.com/", usesWww = true,
        httpsRedirect = true, finalUrl = "https://www.acme.com/", statusCode = 200,
        ip = "104.26.1.1", hostingProvider = "Cloudflare", asn = "AS13335 Cloudflare", cdn = "Cloudflare",
        cms = "WordPress", pageBuilder = "Divi",
        certIssuer = "Let's Encrypt", certValidTo = 1800000000000L, certSigAlg = "SHA256withRSA",
        dns = listOf(SiteDnsRecord("A", "104.26.1.1"), SiteDnsRecord("MX", "aspmx.l.google.com")),
        nameServers = listOf("ns1.domaincontrol.com"), dnsHost = "GoDaddy", registrar = "GoDaddy",
        emailProvider = "Google Workspace", spf = true, dmarc = true,
        integrations = listOf(SiteTech("UserWay", "Accessibility")), analyticsIds = listOf(SiteId("GA4", "G-ABC123")),
        schemaTypes = listOf("LocalBusiness"), businessName = "Acme Plumbing",
        robotsFound = true, pageCount = 42, generatedAt = 1730000000000L, notes = listOf("heads up"),
    )

    @Test fun htmlReportContainsKeyFields() {
        val html = SiteReport.toHtml(profile, "1.21.0")
        assertTrue(html.contains("Website intake"))
        assertTrue(html.contains("Cloudflare"))
        assertTrue(html.contains("UserWay"))
        assertTrue(html.contains("G-ABC123"))
        assertTrue(html.contains("LocalBusiness"))
    }

    @Test fun csvAndJsonAreWellFormed() {
        val csv = SiteReport.toCsv(profile)
        assertTrue(csv.startsWith("Field,Value"))
        assertTrue(csv.contains("Cloudflare"))
        val json = SiteReport.toJson(profile, "1.21.0")
        assertTrue(json.contains("\"domain\""))
        assertTrue(json.contains("integrations"))
    }
}
