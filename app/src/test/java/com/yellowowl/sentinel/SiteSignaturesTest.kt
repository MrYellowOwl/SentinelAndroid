package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class SiteSignaturesTest {
    private val html = """
      <html><head>
      <title>Acme Plumbing &amp; Heating</title>
      <meta name="description" content="Best plumbers in town">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <meta name="generator" content="WordPress 6.5">
      <link rel="canonical" href="https://www.acme.com/">
      <link rel="icon" href="/favicon.ico">
      <script src="https://www.googletagmanager.com/gtag/js?id=G-ABC123DEF4"></script>
      <script>gtag('config', 'G-ABC123DEF4'); fbq('init', '1234567890123456');</script>
      <script src="https://cdn.userway.org/widget.js"></script>
      <link href="https://fonts.googleapis.com/css2?family=Roboto" rel="stylesheet">
      <script src="/wp-content/themes/divi/js/custom.js"></script>
      <script src="https://js.stripe.com/v3/"></script>
      <script type="application/ld+json">{"@type":"LocalBusiness","name":"Acme Plumbing","telephone":"+1-555-123-4567","address":{"streetAddress":"12 Main St","addressLocality":"Springfield","addressRegion":"IL","postalCode":"62704"}}</script>
      </head><body>
      <a href="https://www.facebook.com/acmeplumbing">FB</a>
      <a href="https://www.instagram.com/acme">IG</a>
      <footer>&copy; 2019 Acme Plumbing</footer>
      </body></html>
    """

    @Test fun detectsPlatformStackAndIntegrations() {
        val t = SiteSignatures.detect(html, mapOf("server" to "nginx", "cf-ray" to "abc", "x-powered-by" to "PHP/8.1"))
        assertEquals("WordPress", t.cms)
        assertEquals("Divi", t.pageBuilder)
        assertEquals("Cloudflare", t.cdn)
        assertTrue(t.integrations.any { it.name == "UserWay" && it.category == "Accessibility" })
        assertTrue(t.integrations.any { it.name == "Google Analytics 4" })
        assertTrue(t.integrations.any { it.name == "Meta Pixel" })
        assertTrue(t.integrations.any { it.name == "Stripe" })
        assertTrue(t.fonts.contains("Google Fonts"))
    }

    @Test fun extractsSocialAndAnalyticsIds() {
        val t = SiteSignatures.detect(html, emptyMap())
        assertTrue(t.socialLinks.any { it.label == "Facebook" && it.url.contains("acmeplumbing") })
        assertTrue(t.socialLinks.any { it.label == "Instagram" })
        assertTrue(t.analyticsIds.any { it.kind == "GA4" && it.value == "G-ABC123DEF4" })
        assertTrue(t.analyticsIds.any { it.kind == "Meta Pixel" && it.value == "1234567890123456" })
    }

    @Test fun parsesMetaAndBusinessInfo() {
        val m = SiteSignatures.meta(html)
        assertEquals("Acme Plumbing & Heating", m.title)
        assertEquals("Best plumbers in town", m.description)
        assertEquals("https://www.acme.com/", m.canonical)
        assertEquals("WordPress 6.5", m.generator)
        assertTrue(m.schemaTypes.contains("LocalBusiness"))
        assertEquals("Acme Plumbing", m.businessName)
        assertEquals("+1-555-123-4567", m.businessPhone)
        assertTrue(m.businessAddress?.contains("12 Main St") == true)
        assertEquals("2019", m.copyrightYear)
    }

    @Test fun whoisParsesRegistrarDatesAndNameservers() {
        val who = WhoisParse.parse(
            "Domain Name: ACME.COM\n" +
                "Registrar: GoDaddy.com, LLC\n" +
                "Registrar WHOIS Server: whois.godaddy.com\n" +
                "Creation Date: 2001-05-03T00:00:00Z\n" +
                "Registry Expiry Date: 2026-05-03T00:00:00Z\n" +
                "Name Server: NS1.DOMAINCONTROL.COM\n" +
                "Name Server: NS2.DOMAINCONTROL.COM\n"
        )
        assertEquals("GoDaddy.com, LLC", who.registrar)
        assertTrue(who.created?.startsWith("2001") == true)
        assertTrue(who.expiry?.startsWith("2026") == true)
        assertEquals(listOf("ns1.domaincontrol.com", "ns2.domaincontrol.com"), who.nameServers)
    }

    @Test fun internalLinksResolveAndFilterToSameSite() {
        val h = "<a href='/about'>a</a><a href='https://acme.com/blog'>b</a>" +
            "<a href='https://other.com/x'>ext</a><a href='mailto:a@b.com'>m</a><a href='#top'>t</a>" +
            "<a href='https://www.acme.com/contact'>c</a>"
        val links = SiteSignatures.internalLinks(h, "https://acme.com/", "www.acme.com")
        assertTrue(links.contains("https://acme.com/about"))
        assertTrue(links.contains("https://www.acme.com/contact"))
        assertFalse(links.any { it.contains("other.com") })
        assertFalse(links.any { it.contains("mailto") })
        assertEquals(3, links.size)
    }

    @Test fun infersProviders() {
        assertEquals("GoDaddy", WebInfer.dnsHost(listOf("ns1.domaincontrol.com")))
        assertEquals("Cloudflare", WebInfer.hostingProvider("AS13335 Cloudflare, Inc.", null))
        assertEquals("Google Workspace", WebInfer.emailProvider(listOf("aspmx.l.google.com")))
        assertEquals("Microsoft 365", WebInfer.emailProvider(listOf("acme-com.mail.protection.outlook.com")))
    }
}
