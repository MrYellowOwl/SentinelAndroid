package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class WebScoreTest {
    private val html = """
      <html lang="en"><head>
      <title>Acme Plumbing and Heating Services in Springfield</title>
      <meta name="description" content="Acme Plumbing offers 24/7 emergency plumbing and heating repair across Springfield with licensed techs you can trust.">
      <meta property="og:title" content="Acme">
      <link rel="canonical" href="https://www.acme.com/">
      <link rel="icon" href="/favicon.ico">
      <link rel="stylesheet" href="/style.css">
      <script src="/app.js"></script>
      <script type="application/ld+json">{"@type":"LocalBusiness","name":"Acme","sameAs":["https://facebook.com/acme"],"author":"Jane"}</script>
      </head><body>
      <h1>Welcome to Acme Plumbing</h1><h2>Services</h2><h2>About</h2>
      <img src="a.jpg" alt="plumber at work"><img src="b.jpg">
      <p>${"word ".repeat(700)}</p>
      <a href="/privacy-policy">Privacy</a><a href="/contact-us">Contact</a>
      <a href="mailto:info@acme.com">Email</a><a href="tel:+15551234567">Call</a>
      </body></html>
    """

    @Test fun pageSignalsExtractStructure() {
        val s = SiteSignatures.pageSignals(html, "https://www.acme.com/")
        assertEquals(1, s.h1Count); assertEquals(2, s.h2Count)
        assertEquals(2, s.imgCount); assertEquals(1, s.imgWithAlt)
        assertEquals("en", s.htmlLang)
        assertTrue(s.hasOpenGraph); assertTrue(s.hasSameAs); assertTrue(s.hasAuthor)
        assertTrue(s.wordCount >= 600)
        assertTrue(s.keyPages.any { it.label == "Privacy policy" })
        assertTrue(s.emails.contains("info@acme.com"))
    }

    @Test fun seoScoreIsWeightedAndGraded() {
        val s = SiteSignatures.pageSignals(html, "https://www.acme.com/")
        val seo = SiteScore.seo(s, "Acme Plumbing and Heating Services in Springfield",
            "Acme Plumbing offers 24/7 emergency plumbing and heating repair across Springfield with licensed techs you can trust.",
            "https://www.acme.com/", "width=device-width", true, true, true, listOf("LocalBusiness"), "/favicon.ico", true, true, true, 400, 50_000)
        assertTrue("seo=${seo.score}", seo.score >= 85)
        assertTrue(seo.categories.any { it.name == "Content" })
        assertTrue(seo.categories.any { it.name == "Technical" })
        assertTrue(seo.categories.any { it.name == "Performance" })
    }

    @Test fun seoScoreIsStrictOnWeakPage() {
        // No title, noindex, no schema, slow — should score low.
        val weak = SiteSignatures.pageSignals("<html><body><p>hi</p></body></html>", null)
        val seo = SiteScore.seo(weak, null, null, null, null, false, false, false, emptyList(), null, false, false, false, 3000, 2_000_000)
        assertTrue("seo=${seo.score}", seo.score < 40)
        assertEquals("F", seo.grade)
    }

    @Test fun robotsAiCrawlerAnalysis() {
        val robots = "User-agent: GPTBot\nDisallow: /\n\nUser-agent: *\nDisallow: /wp-admin/\nAllow: /\n"
        assertEquals(listOf("GPTBot"), SiteScore.blockedAiCrawlers(robots))
        assertFalse(SiteScore.starBlocksAll(robots))
        assertTrue(SiteScore.starBlocksAll("User-agent: *\nDisallow: /"))
    }

    @Test fun aiScoreFailsCrawlerAccessWhenBlocked() {
        val s = SiteSignatures.pageSignals(html, null)
        val ai = SiteScore.ai(s, listOf("GPTBot"), false, false, listOf("LocalBusiness"), "Acme", "desc", "https://x/", true)
        assertEquals(CheckStatus.FAIL, ai.checks.first { it.label.startsWith("Allows AI") }.status)
        assertTrue(ai.score in 1..99)
    }

    @Test fun accessibilityScoreAndSignals() {
        val good = "<html lang='en'><head><title>Acme Plumbers of Springfield IL</title>" +
            "<meta name='viewport' content='width=device-width, initial-scale=1'></head>" +
            "<body><a href='#main'>Skip to content</a><main><h1>Acme</h1><h2>Services</h2>" +
            "<img src=a alt='team'><img src=b alt='van'>" +
            "<form><label for='e'>Email</label><input id='e' type='text'></form>" +
            "<a href='/about'>About us</a><a href='/contact'>Contact</a></main></body></html>"
        val s = SiteSignatures.pageSignals(good, "https://acme.com/")
        assertTrue(s.hasLandmarks); assertTrue(s.hasSkipLink); assertTrue(s.zoomAllowed)
        assertEquals(1, s.inputCount); assertEquals(1, s.inputsLabeled)
        val a = SiteScore.accessibility(s, "Acme Plumbers of Springfield IL")
        assertTrue("a11y=${a.score}", a.score >= 90)

        val bad = "<html><head><meta name='viewport' content='user-scalable=no'></head><body><img src=a><form><input type='text'></form></body></html>"
        val sb = SiteSignatures.pageSignals(bad, null)
        assertFalse(sb.zoomAllowed)
        assertTrue(SiteScore.accessibility(sb, null).score < 40)
    }

    @Test fun stackVersionsAndOutdated() {
        val html = "<meta name='generator' content='WordPress 6.5'><script src='/jquery-2.2.4.min.js'></script>"
        val v = SiteSignatures.versions(html, mapOf("x-powered-by" to "PHP/7.4.3"))
        assertEquals("6.5", v["WordPress"]); assertEquals("2.2.4", v["jQuery"]); assertEquals("7.4.3", v["PHP"])
        val out = SiteSignatures.outdatedStack(v)
        assertTrue(out.any { it.contains("jQuery") }); assertTrue(out.any { it.contains("PHP") })
        assertFalse(out.any { it.contains("WordPress") })
    }

    @Test fun attentionFlagsFire() {
        val flags = SiteScore.attentionFlags(
            httpsEnforced = false, hsts = false, compression = false,
            certValidTo = System.currentTimeMillis() + 10L * 86_400_000, sslWeak = false,
            domainExpiryDays = 20, blockedAi = listOf("GPTBot"), starBlocksAll = false,
            title = null, description = null, h1Count = 0, noindex = false, dmarc = false,
            schemaTypes = emptyList(), mixedContent = false, responseMs = 2500,
            copyrightYear = "2018", currentYear = 2026, now = System.currentTimeMillis()
        )
        assertTrue(flags.any { it.contains("HTTPS") })
        assertTrue(flags.any { it.contains("expires in") })
        assertTrue(flags.any { it.contains("GPTBot") })
        assertTrue(flags.any { it.contains("DMARC") })
        assertTrue(flags.any { it.contains("Slow server") })
        assertTrue(flags.any { it.contains("2018") })
    }
}
