package com.yellowowl.sentinel

/**
 * Pure signature detection over a page's HTML + response headers: CMS/platform, JS framework, page
 * builder, every recognizable third-party integration (analytics, accessibility, chat, CRM, consent,
 * payments, reviews, scheduling, maps…), social links, migratable tag IDs, and the SEO/meta/business
 * block. No I/O — [SiteIntake] fetches the page and passes it here, so this is fully unit-testable.
 */
object SiteSignatures {

    data class TechResult(
        val cms: String?,
        val framework: String?,
        val pageBuilder: String?,
        val cdn: String?,
        val integrations: List<SiteTech>,
        val socialLinks: List<SiteLink>,
        val analyticsIds: List<SiteId>,
        val fonts: List<String>,
    )

    data class Meta(
        val title: String?,
        val description: String?,
        val ogTitle: String?,
        val ogImage: String?,
        val favicon: String?,
        val canonical: String?,
        val viewport: String?,
        val generator: String?,
        val schemaTypes: List<String>,
        val businessName: String?,
        val businessPhone: String?,
        val businessAddress: String?,
        val copyrightYear: String?,
    )

    // name, category, and any-of these needles (matched case-insensitively against html+headers)
    private data class Sig(val name: String, val category: String, val needles: List<String>)

    private val integrationSigs = listOf(
        // Analytics / tag managers
        Sig("Google Tag Manager", "Analytics", listOf("googletagmanager.com/gtm.js", "gtm.start")),
        Sig("Google Analytics 4", "Analytics", listOf("googletagmanager.com/gtag/js", "gtag('config', 'g-", "gtag(\"config\", \"g-")),
        Sig("Universal Analytics", "Analytics", listOf("google-analytics.com/analytics.js", "ga('create'")),
        Sig("Meta Pixel", "Analytics", listOf("connect.facebook.net", "fbq('init'", "fbq(\"init\"")),
        Sig("Hotjar", "Analytics", listOf("static.hotjar.com", "hotjar.com/c/hotjar")),
        Sig("Microsoft Clarity", "Analytics", listOf("clarity.ms/tag", "c.clarity.ms")),
        Sig("Plausible", "Analytics", listOf("plausible.io/js")),
        Sig("Matomo", "Analytics", listOf("matomo.js", "piwik.js")),
        Sig("Segment", "Analytics", listOf("cdn.segment.com/analytics")),
        // Accessibility overlays
        Sig("UserWay", "Accessibility", listOf("userway.org")),
        Sig("accessiBe", "Accessibility", listOf("acsbapp.com", "accessibe.com")),
        Sig("AudioEye", "Accessibility", listOf("audioeye.com")),
        Sig("EqualWeb", "Accessibility", listOf("equalweb.com", "nagich.com")),
        // Live chat
        Sig("Intercom", "Chat", listOf("widget.intercom.io", "intercomsettings")),
        Sig("Drift", "Chat", listOf("js.driftt.com", "drift.load")),
        Sig("Tawk.to", "Chat", listOf("embed.tawk.to")),
        Sig("Zendesk", "Chat", listOf("static.zdassets.com", "zendesk.com/embeddable")),
        Sig("LiveChat", "Chat", listOf("cdn.livechatinc.com")),
        Sig("Crisp", "Chat", listOf("client.crisp.chat")),
        Sig("Tidio", "Chat", listOf("code.tidio.co")),
        // CRM / marketing automation
        Sig("HubSpot", "CRM / Marketing", listOf("js.hs-scripts.com", "hs-analytics.net", "hubspotusercontent", "hs-sites.com")),
        Sig("Salesforce Pardot", "CRM / Marketing", listOf("pardot.com", "pi.pardot")),
        Sig("Marketo", "CRM / Marketing", listOf("munchkin.marketo.net")),
        Sig("Mailchimp", "CRM / Marketing", listOf("chimpstatic.com", "list-manage.com")),
        Sig("Klaviyo", "CRM / Marketing", listOf("static.klaviyo.com", "klaviyo.js")),
        Sig("ActiveCampaign", "CRM / Marketing", listOf("activehosted.com")),
        Sig("Constant Contact", "CRM / Marketing", listOf("ctctcdn.com")),
        Sig("Keap / Infusionsoft", "CRM / Marketing", listOf("infusionsoft.com", "keap.com")),
        // Consent / cookie banners
        Sig("OneTrust", "Consent", listOf("cdn.cookielaw.org", "onetrust")),
        Sig("Cookiebot", "Consent", listOf("consent.cookiebot.com")),
        Sig("CookieYes", "Consent", listOf("cookieyes.com", "cookie-law-info")),
        Sig("Osano", "Consent", listOf("osano.com")),
        Sig("Termly", "Consent", listOf("termly.io")),
        // Scheduling / booking
        Sig("Calendly", "Scheduling", listOf("calendly.com")),
        Sig("Acuity", "Scheduling", listOf("acuityscheduling.com")),
        Sig("Setmore", "Scheduling", listOf("setmore.com")),
        // Payments
        Sig("Stripe", "Payments", listOf("js.stripe.com")),
        Sig("PayPal", "Payments", listOf("paypal.com/sdk", "paypalobjects.com")),
        Sig("Square", "Payments", listOf("squareup.com", "web.squarecdn.com")),
        // Reviews
        Sig("Trustpilot", "Reviews", listOf("widget.trustpilot.com")),
        Sig("Birdeye", "Reviews", listOf("birdeye.com")),
        Sig("Podium", "Reviews", listOf("podium.com")),
        Sig("Yelp", "Reviews", listOf("yelp.com/biz", "yelp.com/embed")),
        // Maps / captcha / media / testing
        Sig("Google Maps", "Maps", listOf("maps.googleapis.com", "google.com/maps/embed")),
        Sig("reCAPTCHA", "Security", listOf("google.com/recaptcha", "grecaptcha")),
        Sig("hCaptcha", "Security", listOf("hcaptcha.com")),
        Sig("Optimizely", "A/B testing", listOf("cdn.optimizely.com")),
        Sig("VWO", "A/B testing", listOf("visualwebsiteoptimizer", "dev.visualwebsiteoptimizer")),
        Sig("Vimeo", "Media", listOf("player.vimeo.com")),
        Sig("Wistia", "Media", listOf("fast.wistia")),
        Sig("YouTube embed", "Media", listOf("youtube.com/embed", "youtube-nocookie.com")),
    )

    private val cmsSigs = listOf(
        Sig("WordPress", "", listOf("wp-content", "wp-includes", "/wp-json")),
        Sig("Shopify", "", listOf("cdn.shopify.com", "shopify.theme", "myshopify.com")),
        Sig("Wix", "", listOf("static.parastorage.com", "wix.com", "wixstatic.com")),
        Sig("Squarespace", "", listOf("static1.squarespace.com", "squarespace.com")),
        Sig("Webflow", "", listOf("assets.website-files.com", "webflow.io", "data-wf-")),
        Sig("Drupal", "", listOf("drupal.settings", "/sites/default/files", "/core/misc/drupal.js")),
        Sig("Joomla", "", listOf("/media/jui/", "/media/system/js/", "option=com_")),
        Sig("Ghost", "", listOf("content/images/", "ghost-sdk", "casper")),
        Sig("Duda", "", listOf("irp.cdn-website.com", "dudaone", "dudamobile")),
        Sig("GoDaddy Website Builder", "", listOf("img1.wsimg.com")),
        Sig("BigCommerce", "", listOf("bigcommerce.com", "cdn11.bigcommerce.com")),
        Sig("HubSpot CMS", "", listOf("hs-sites.com", "hubspotusercontent")),
    )

    private val frameworkSigs = listOf(
        Sig("Next.js", "", listOf("/_next/static", "__next_data__")),
        Sig("Nuxt", "", listOf("__nuxt__", "/_nuxt/")),
        Sig("Gatsby", "", listOf("___gatsby", "/page-data/")),
        Sig("React", "", listOf("data-reactroot", "react-dom", "_reactrootcontainer")),
        Sig("Vue.js", "", listOf("data-v-", "vue.runtime", "__vue__")),
        Sig("Angular", "", listOf("ng-version", "angular.min.js")),
        Sig("Svelte", "", listOf("svelte-", "/_app/immutable/")),
        Sig("jQuery", "", listOf("jquery.min.js", "jquery.js", "/jquery-")),
    )

    private val builderSigs = listOf(
        Sig("Elementor", "", listOf("elementor-frontend", "/elementor/", "elementor-element")),
        Sig("Divi", "", listOf("et_pb_", "/divi/", "et-core")),
        Sig("WPBakery", "", listOf("js_composer", "wpb_")),
        Sig("Beaver Builder", "", listOf("fl-builder")),
        Sig("Oxygen", "", listOf("oxygen-builder", "ct_section")),
        Sig("Bricks", "", listOf("/bricks/", "brxe-")),
    )

    private val fontSigs = listOf(
        "Google Fonts" to listOf("fonts.googleapis.com", "fonts.gstatic.com"),
        "Adobe Fonts (Typekit)" to listOf("use.typekit.net", "typekit.com"),
        "Font Awesome" to listOf("fontawesome", "font-awesome"),
    )

    private val socialHosts = listOf(
        "Facebook" to "facebook.com", "Instagram" to "instagram.com", "X (Twitter)" to "twitter.com",
        "X (Twitter)" to "x.com", "LinkedIn" to "linkedin.com", "YouTube" to "youtube.com",
        "TikTok" to "tiktok.com", "Pinterest" to "pinterest.com", "Yelp" to "yelp.com",
        "WhatsApp" to "wa.me", "Telegram" to "t.me",
    )

    fun detect(html: String, headers: Map<String, String>): TechResult {
        val hay = (html + "\n" + headers.entries.joinToString("\n") { "${it.key}: ${it.value}" }).lowercase()
        fun firstMatch(sigs: List<Sig>): String? = sigs.firstOrNull { s -> s.needles.any { hay.contains(it) } }?.name

        val integrations = integrationSigs
            .filter { s -> s.needles.any { hay.contains(it) } }
            .map { SiteTech(it.name, it.category) }
            .distinctBy { it.name }

        val fonts = fontSigs.filter { (_, needles) -> needles.any { hay.contains(it) } }.map { it.first }

        // CDN mostly shows up in headers.
        val cdn = when {
            headers.keys.any { it.equals("cf-ray", true) } || hay.contains("cloudflare") -> "Cloudflare"
            headers.keys.any { it.equals("x-amz-cf-id", true) } || hay.contains("cloudfront") -> "Amazon CloudFront"
            (headers["via"]?.contains("fastly", true) == true) || headers.keys.any { it.equals("x-served-by", true) && headers[it]?.contains("fastly", true) == true } -> "Fastly"
            headers.keys.any { it.startsWith("x-akamai", true) } || hay.contains("akamai") -> "Akamai"
            hay.contains("sucuri") -> "Sucuri"
            else -> null
        }

        return TechResult(
            cms = firstMatch(cmsSigs),
            framework = firstMatch(frameworkSigs),
            pageBuilder = firstMatch(builderSigs),
            cdn = cdn,
            integrations = integrations,
            socialLinks = socialLinks(html),
            analyticsIds = analyticsIds(html),
            fonts = fonts,
        )
    }

    private fun socialLinks(html: String): List<SiteLink> {
        val urls = Regex("""https?://[^\s"'<>)]+""", RegexOption.IGNORE_CASE).findAll(html).map { it.value.trimEnd('"', '\'', ')', '.') }.toList()
        val out = LinkedHashMap<String, SiteLink>()   // one per platform (first seen)
        for ((label, host) in socialHosts) {
            val match = urls.firstOrNull { it.contains(host, ignoreCase = true) &&
                !it.contains("sharer", true) && !it.contains("/share", true) && !it.contains("intent/tweet", true) }
            if (match != null && !out.containsKey(label)) out[label] = SiteLink(label, match)
        }
        return out.values.toList()
    }

    private fun analyticsIds(html: String): List<SiteId> {
        val out = LinkedHashSet<SiteId>()
        Regex("""G-[A-Z0-9]{6,12}""").findAll(html).forEach { out.add(SiteId("GA4", it.value)) }
        Regex("""GTM-[A-Z0-9]{4,10}""").findAll(html).forEach { out.add(SiteId("GTM", it.value)) }
        Regex("""UA-\d{4,10}-\d{1,4}""").findAll(html).forEach { out.add(SiteId("Universal Analytics", it.value)) }
        Regex("""AW-\d{6,12}""").findAll(html).forEach { out.add(SiteId("Google Ads", it.value)) }
        Regex("""fbq\(\s*['"]init['"]\s*,\s*['"](\d{8,20})['"]""").findAll(html).forEach { out.add(SiteId("Meta Pixel", it.groupValues[1])) }
        return out.toList()
    }

    // --------------------------------------------------------------- SEO / meta / business

    fun meta(html: String): Meta {
        fun metaContent(attr: String, name: String): String? =
            Regex("""<meta[^>]*\b$attr\s*=\s*["']${Regex.escape(name)}["'][^>]*>""", RegexOption.IGNORE_CASE)
                .find(html)?.value?.let { tag -> Regex("""content\s*=\s*["']([^"']*)["']""", RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1)?.trim() }
                ?.takeIf { it.isNotBlank() }

        fun linkHref(rel: String): String? =
            Regex("""<link[^>]*\brel\s*=\s*["'][^"']*${Regex.escape(rel)}[^"']*["'][^>]*>""", RegexOption.IGNORE_CASE)
                .find(html)?.value?.let { tag -> Regex("""href\s*=\s*["']([^"']*)["']""", RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1)?.trim() }
                ?.takeIf { it.isNotBlank() }

        val title = Regex("""<title[^>]*>(.*?)</title>""", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
            .find(html)?.groupValues?.get(1)?.let { decodeEntities(it).trim() }?.takeIf { it.isNotBlank() }

        val ld = jsonLd(html)
        val copyright = Regex("""(?:©|&copy;|copyright)\s*(?:[^0-9]{0,12})?(20\d{2}|19\d{2})""", RegexOption.IGNORE_CASE)
            .findAll(html).mapNotNull { it.groupValues[1].toIntOrNull() }.maxOrNull()?.toString()

        return Meta(
            title = title,
            description = metaContent("name", "description"),
            ogTitle = metaContent("property", "og:title"),
            ogImage = metaContent("property", "og:image"),
            favicon = linkHref("icon"),
            canonical = linkHref("canonical"),
            viewport = metaContent("name", "viewport"),
            generator = metaContent("name", "generator"),
            schemaTypes = ld.first,
            businessName = ld.second["name"],
            businessPhone = ld.second["telephone"] ?: ld.second["phone"],
            businessAddress = ld.second["address"],
            copyrightYear = copyright,
        )
    }

    /** Extracts JSON-LD @type values and a few business fields (name/telephone/address) best-effort. */
    private fun jsonLd(html: String): Pair<List<String>, Map<String, String>> {
        val blocks = Regex("""<script[^>]*type\s*=\s*["']application/ld\+json["'][^>]*>(.*?)</script>""",
            setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)).findAll(html).map { it.groupValues[1] }.toList()
        val types = LinkedHashSet<String>()
        val fields = HashMap<String, String>()
        for (b in blocks) {
            Regex("""["']@type["']\s*:\s*["']([^"']+)["']""").findAll(b).forEach { types.add(it.groupValues[1]) }
            fun grab(key: String) = Regex(""""$key"\s*:\s*"([^"]{2,120})"""").find(b)?.groupValues?.get(1)?.let { decodeEntities(it).trim() }
            grab("name")?.let { fields.putIfAbsent("name", it) }
            grab("telephone")?.let { fields.putIfAbsent("telephone", it) }
            // address can be a nested object with streetAddress/addressLocality…
            val street = grab("streetAddress"); val city = grab("addressLocality"); val region = grab("addressRegion"); val zip = grab("postalCode")
            val addr = listOfNotNull(street, city, region, zip).joinToString(", ").ifBlank { null }
            addr?.let { fields.putIfAbsent("address", it) }
        }
        return types.toList() to fields
    }

    private fun decodeEntities(s: String): String = s
        .replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'").replace("&nbsp;", " ")

    // --------------------------------------------------------------- structural page signals (for scoring)

    data class PageSignals(
        val h1Count: Int,
        val h2Count: Int,
        val imgCount: Int,
        val imgWithAlt: Int,
        val htmlLang: String?,
        val noindex: Boolean,
        val hasOpenGraph: Boolean,
        val hasSameAs: Boolean,
        val hasAuthor: Boolean,
        val wordCount: Int,
        val scriptCount: Int,
        val stylesheetCount: Int,
        val scriptsInHead: Int,
        val keyPages: List<SiteLink>,
        val emails: List<String>,
        val phones: List<String>,
    )

    private val keyPagePatterns = listOf(
        "Privacy policy" to listOf("/privacy", "privacy-policy"),
        "Terms" to listOf("/terms", "terms-of", "/tos"),
        "Contact" to listOf("/contact"),
        "About" to listOf("/about"),
        "Blog" to listOf("/blog", "/news", "/articles"),
        "Shop / store" to listOf("/shop", "/store", "/products", "/cart"),
        "Careers" to listOf("/careers", "/jobs"),
    )

    fun pageSignals(html: String, baseUrl: String?): PageSignals {
        val lower = html.lowercase()
        val h1 = Regex("<h1[\\s>]", RegexOption.IGNORE_CASE).findAll(html).count()
        val h2 = Regex("<h2[\\s>]", RegexOption.IGNORE_CASE).findAll(html).count()
        val hasSameAs = lower.contains("\"sameas\"") || lower.contains("'sameas'")
        val hasAuthor = Regex("""["']author["']\s*:""", RegexOption.IGNORE_CASE).containsMatchIn(html) ||
            Regex("""<meta[^>]*\bname\s*=\s*["']author["']""", RegexOption.IGNORE_CASE).containsMatchIn(html)
        val imgs = Regex("<img\\b[^>]*>", RegexOption.IGNORE_CASE).findAll(html).map { it.value }.toList()
        val imgWithAlt = imgs.count { Regex("""\balt\s*=\s*["'][^"']+["']""", RegexOption.IGNORE_CASE).containsMatchIn(it) }
        val htmlLang = Regex("""<html[^>]*\blang\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE).find(html)?.groupValues?.get(1)?.trim()
        val robotsMeta = Regex("""<meta[^>]*\bname\s*=\s*["']robots["'][^>]*>""", RegexOption.IGNORE_CASE).find(html)?.value?.lowercase().orEmpty()
        val noindex = robotsMeta.contains("noindex")
        val hasOg = lower.contains("property=\"og:") || lower.contains("property='og:")
        val text = html
            .replace(Regex("<script\\b[^<]*(?:(?!</script>)<[^<]*)*</script>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)), " ")
            .replace(Regex("<style\\b[^<]*(?:(?!</style>)<[^<]*)*</style>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)), " ")
            .replace(Regex("<[^>]+>"), " ")
        val wordCount = text.split(Regex("\\s+")).count { it.length > 1 }
        val scriptCount = Regex("<script\\b", RegexOption.IGNORE_CASE).findAll(html).count()
        val stylesheetCount = Regex("""<link[^>]*rel\s*=\s*["'][^"']*stylesheet""", RegexOption.IGNORE_CASE).findAll(html).count()
        val head = Regex("<head\\b.*?</head>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL)).find(html)?.value.orEmpty()
        val scriptsInHead = Regex("<script\\b[^>]*\\bsrc\\s*=", RegexOption.IGNORE_CASE).findAll(head).count()

        // Links → key pages.
        val hrefs = Regex("""href\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE).findAll(html).map { it.groupValues[1] }.toList()
        fun resolve(href: String): String = when {
            href.startsWith("http", true) -> href
            baseUrl == null -> href
            else -> runCatching { java.net.URI(baseUrl).resolve(href).toString() }.getOrDefault(href)
        }
        val keyPages = LinkedHashMap<String, SiteLink>()
        for ((label, pats) in keyPagePatterns) {
            val match = hrefs.firstOrNull { h -> pats.any { h.lowercase().contains(it) } }
            if (match != null && !keyPages.containsKey(label)) keyPages[label] = SiteLink(label, resolve(match))
        }
        val emails = (Regex("""mailto:([^"'?\s]+)""", RegexOption.IGNORE_CASE).findAll(html).map { it.groupValues[1] } +
            Regex("""[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}""").findAll(text).map { it.value })
            .map { it.lowercase().trim() }.filter { !it.endsWith(".png") && !it.endsWith(".jpg") }.distinct().take(10)
        val phones = Regex("""tel:([+0-9().\-\s]{7,})""", RegexOption.IGNORE_CASE).findAll(html)
            .map { it.groupValues[1].trim() }.distinct().take(10).toList()

        return PageSignals(h1, h2, imgs.size, imgWithAlt, htmlLang, noindex, hasOg, hasSameAs, hasAuthor, wordCount, scriptCount, stylesheetCount, scriptsInHead, keyPages.values.toList(), emails.toList(), phones)
    }
}
