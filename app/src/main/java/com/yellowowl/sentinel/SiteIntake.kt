package com.yellowowl.sentinel

import java.net.InetSocketAddress
import java.net.URLEncoder
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext

/**
 * Collects a comprehensive "site intake" profile for the web-developer mode of the website tool.
 * All reads are passive and read-only (DNS, WHOIS, the public cert, one homepage fetch, robots/sitemap,
 * ip-api for ASN). The parsing is done by the pure [SiteSignatures] / [WhoisParse] / [WebInfer].
 */
object SiteIntake {

    private data class CertData(
        val issuer: String?, val subject: String?, val validFrom: Long?, val validTo: Long?,
        val sigAlg: String?, val sans: List<String>,
    )

    private suspend fun fetch(url: String): Http.Result? =
        runCatching { Http.get(url, timeoutMillis = 12_000, maxBytes = 768 * 1024) }.getOrNull()

    suspend fun collect(input: String): Result<SiteProfile> = withContext(Dispatchers.IO) {
        val notes = ArrayList<String>()
        val url = runCatching { WebChecks.normalizeUrl(input) }.getOrNull()
            ?: return@withContext Result.failure(IllegalArgumentException("Enter a valid domain or URL, e.g. example.com"))
        val inputHost = url.host.lowercase()
        val apex = inputHost.removePrefix("www.")

        // 1. Load the homepage, following redirects so we see the canonical host/scheme.
        val t0 = System.currentTimeMillis()
        val primary = fetch("https://$apex/") ?: fetch("https://www.$apex/") ?: fetch(url.toString())
        val responseMs = if (primary != null) System.currentTimeMillis() - t0 else null
        if (primary == null) notes.add("Couldn't load the site over HTTPS — hosting/stack fields may be blank; DNS and WHOIS still ran.")
        val finalUrl = primary?.finalUrl
        val canonicalHost = (finalUrl?.host ?: inputHost).lowercase()
        val scheme = finalUrl?.protocol ?: "https"
        val canonicalUrl = "$scheme://$canonicalHost/"
        val html = primary?.body.orEmpty()
        val headerMap = primary?.headers?.mapValues { it.value.firstOrNull().orEmpty() } ?: emptyMap()

        val httpsRedirect = runCatching {
            val r = Http.get("http://$apex/", followRedirects = false, timeoutMillis = 6_000)
            r != null && WebChecks.isRedirect(r.code) && (r.header("location")?.startsWith("https", true) == true)
        }.getOrDefault(scheme == "https")

        // 2. DNS (all record types), plus email posture, in parallel.
        suspend fun dns(type: String, name: String = apex) = NetToolsNet.dnsLookup(name, type).getOrNull().orEmpty()
        val results = coroutineScope {
            val types = listOf("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
            val jobs = types.map { type -> type to async { dns(type) } }
            val dmarcJob = async { dns("TXT", "_dmarc.$apex") }
            val dkimJob = async {
                listOf("google._domainkey", "selector1._domainkey", "selector2._domainkey", "default._domainkey", "k1._domainkey")
                    .any { runCatching { dns("TXT", "$it.$apex") }.getOrNull()?.isNotEmpty() == true }
            }
            val resolved = HashMap<String, List<NetToolsNet.DnsAnswer>>()
            for ((type, job) in jobs) resolved[type] = job.await()
            Triple(resolved, dmarcJob.await(), dkimJob.await())
        }
        val byType = results.first
        fun recs(t: String) = byType[t].orEmpty()
        val allDns = listOf("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
            .flatMap { t -> recs(t) }.map { SiteDnsRecord(it.type, it.value) }
        val ip = recs("A").firstOrNull()?.value
        val dnsNameServers = recs("NS").map { it.value.trimEnd('.').lowercase() }.distinct()
        val mxHosts = recs("MX").map { it.value }
        val spf = recs("TXT").any { it.value.contains("v=spf1", true) }
        val dmarc = results.second.any { it.value.contains("v=DMARC1", true) }
        val dkimHint = results.third

        // 3. Hosting / ASN from ip-api (keyless).
        var asn: String? = null
        var hosting: String? = null
        var hostingLocation: String? = null
        if (ip != null) {
            val info = runCatching {
                Http.get("http://ip-api.com/json/$ip?fields=status,message,query,isp,org,as,city,country", timeoutMillis = 8_000)
                    ?.body?.let { IpExposure.parseInfo(it) }
            }.getOrNull()
            asn = info?.asn
            hostingLocation = info?.location
            hosting = WebInfer.hostingProvider(listOfNotNull(info?.asn, info?.org, info?.isp).joinToString(" "), headerMap["server"])
        }

        // 4. Certificate (issuer / validity / SANs).
        val cert = readCert(canonicalHost)

        // 5. WHOIS (registrar, dates, name servers).
        val who = runCatching { NetToolsNet.whois(apex).getOrNull()?.let { WhoisParse.parse(it) } }.getOrNull()
        val nameServers = who?.nameServers?.takeIf { it.isNotEmpty() } ?: dnsNameServers

        // 6. HTML signatures + meta.
        val tech = SiteSignatures.detect(html, headerMap)
        val meta = SiteSignatures.meta(html)

        // 7. robots.txt + sitemap → page inventory.
        val robots = fetch("${canonicalUrl}robots.txt")
        val robotsFound = robots != null && robots.code in 200..299
        val sitemapRefs = (robots?.body?.lineSequence()
            ?.mapNotNull { l -> l.trim().takeIf { it.startsWith("Sitemap:", true) }?.substringAfter(':')?.substringAfter(':')?.trim() }
            ?.toList().orEmpty()).ifEmpty { listOf("${canonicalUrl}sitemap.xml") }
        var pageCount: Int? = null
        val firstSitemap = sitemapRefs.firstOrNull()?.let { ref -> fetch(if (ref.startsWith("http")) ref else "$canonicalUrl${ref.trimStart('/')}") }
        if (firstSitemap != null && firstSitemap.code in 200..299) {
            val locs = Regex("<loc>\\s*(.*?)\\s*</loc>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                .findAll(firstSitemap.body).count()
            if (locs > 0) {
                pageCount = locs
                if (firstSitemap.body.contains("<sitemapindex", true)) notes.add("Sitemap is an index of $locs child sitemaps; true page count is higher.")
            }
        }

        // 8. CMS admin path (best-effort, by platform).
        val cmsAdmin = when (tech.cms) {
            "WordPress" -> "${canonicalUrl}wp-login.php"
            "Shopify" -> "${canonicalUrl}admin"
            "Joomla" -> "${canonicalUrl}administrator/"
            "Drupal" -> "${canonicalUrl}user/login"
            "Ghost" -> "${canonicalUrl}ghost/"
            else -> null
        }

        // 9. Presence search links (profile detection needs provider APIs; a ready search is the honest help).
        val q = meta.businessName ?: apex
        fun enc(s: String) = URLEncoder.encode(s, "UTF-8")
        val presence = listOf(
            SiteLink("Google Business (search)", "https://www.google.com/search?q=${enc(q)}"),
            SiteLink("Google Maps (search)", "https://www.google.com/maps/search/${enc(q)}"),
            SiteLink("Yelp (search)", "https://www.yelp.com/search?find_desc=${enc(q)}"),
        )

        // 10. Scores + flags + extras (page signals, AI-crawler access, perf, DNS security).
        val now = System.currentTimeMillis()
        val currentYear = java.util.GregorianCalendar().get(java.util.Calendar.YEAR)
        val signals = SiteSignatures.pageSignals(html, canonicalUrl)
        val robotsBody = robots?.body.orEmpty()
        val blockedAi = SiteScore.blockedAiCrawlers(robotsBody)
        val starBlocksAll = SiteScore.starBlocksAll(robotsBody)
        val llmsTxt = runCatching { fetch("${canonicalUrl}llms.txt")?.let { it.code in 200..299 && it.body.isNotBlank() } }.getOrNull() ?: false
        val hasSitemap = firstSitemap != null && firstSitemap.code in 200..299
        val hasAnalytics = tech.integrations.any { it.category == "Analytics" }
        val caa = recs("CAA").isNotEmpty()
        val dnssec = runCatching {
            Http.get("https://dns.google/resolve?name=$apex&type=DNSKEY", timeoutMillis = 6_000)?.body
                ?.let { Regex("\"type\"\\s*:\\s*48").containsMatchIn(it) }
        }.getOrNull() ?: false
        val sslWeak = cert?.sigAlg?.uppercase()?.let { it.contains("SHA1") || it.contains("MD5") } ?: false
        val sslGrade = when {
            cert == null -> null
            cert.validTo != null && cert.validTo < now -> "Expired"
            sslWeak -> "Weak (SHA-1)"
            cert.issuer != null -> "OK"
            else -> null
        }
        val mixedContent = scheme == "https" && Regex("""(src|href)\s*=\s*["']http://""", RegexOption.IGNORE_CASE).containsMatchIn(html)
        val domainExpiryDays = who?.expiry?.let { s ->
            Regex("""(\d{4})-(\d{2})-(\d{2})""").find(s)?.let { m ->
                runCatching {
                    val cal = java.util.GregorianCalendar(m.groupValues[1].toInt(), m.groupValues[2].toInt() - 1, m.groupValues[3].toInt())
                    ((cal.timeInMillis - now) / 86_400_000L).toInt()
                }.getOrNull()
            }
        }
        val hsts = !headerMap["strict-transport-security"].isNullOrBlank()
        val compression = headerMap["content-encoding"]?.lowercase()
            ?.let { it.contains("gzip") || it.contains("br") || it.contains("deflate") || it.contains("zstd") } ?: false
        val htmlBytes = html.length.takeIf { it > 0 }
        val seo = SiteScore.seo(signals, meta.title, meta.description, meta.canonical, meta.viewport, httpsRedirect, hsts, compression,
            meta.schemaTypes, meta.favicon, robotsFound, hasSitemap, hasAnalytics, responseMs, htmlBytes)
        val aiScore = SiteScore.ai(signals, blockedAi, starBlocksAll, llmsTxt, meta.schemaTypes, meta.title, meta.description, meta.canonical, hasSitemap)
        val a11y = SiteScore.accessibility(signals, meta.title)
        val versions = SiteSignatures.versions(html, headerMap)
        val secHeaders = linkedMapOf(
            "Content-Security-Policy" to !headerMap["content-security-policy"].isNullOrBlank(),
            "X-Frame-Options" to !headerMap["x-frame-options"].isNullOrBlank(),
            "X-Content-Type-Options" to !headerMap["x-content-type-options"].isNullOrBlank(),
            "Referrer-Policy" to !headerMap["referrer-policy"].isNullOrBlank(),
            "Permissions-Policy" to !headerMap["permissions-policy"].isNullOrBlank(),
            "Strict-Transport-Security" to hsts,
        )
        // Deeper checks (parallel): redirect trace, broken-link sampling, multi-page content sampling.
        val deep = coroutineScope {
            val redirJob = async { traceRedirects("http://$apex/") }
            val internal = SiteSignatures.internalLinks(html, canonicalUrl, canonicalHost)
            val brokenJob = async { sampleBrokenLinks(internal.take(12)) }
            val sampleJob = async { samplePages(internal, canonicalUrl) }
            Triple(redirJob.await(), brokenJob.await(), sampleJob.await())
        }
        val redirectChain = deep.first
        val brokenLinks = deep.second
        val sampledPages = deep.third

        val baseFlags = SiteScore.attentionFlags(httpsRedirect, hsts, compression, cert?.validTo, sslWeak, domainExpiryDays, blockedAi, starBlocksAll,
            meta.title, meta.description, signals.h1Count, signals.noindex, dmarc, meta.schemaTypes, mixedContent, responseMs, meta.copyrightYear, currentYear, now)
        val flags = baseFlags + SiteSignatures.outdatedStack(versions) + buildList {
            if (secHeaders["Content-Security-Policy"] == false) add("No Content-Security-Policy header.")
            if (secHeaders["X-Frame-Options"] == false) add("No X-Frame-Options header (clickjacking risk).")
            if (redirectChain.size > 3) add("${redirectChain.size - 1} redirect hops before the homepage loads.")
            if (brokenLinks.isNotEmpty()) add("${brokenLinks.size} broken link(s) found on the homepage.")
        }

        val cmsLabel = tech.cms ?: meta.generator?.substringBefore(' ')?.takeIf { it.isNotBlank() }
        val profile = SiteProfile(
            input = input,
            domain = apex,
            canonicalUrl = canonicalUrl,
            usesWww = canonicalHost.startsWith("www."),
            httpsRedirect = httpsRedirect,
            finalUrl = finalUrl?.toString() ?: canonicalUrl,
            statusCode = primary?.code,
            ip = ip,
            hostingProvider = hosting,
            asn = asn,
            cdn = tech.cdn,
            serverHeader = headerMap["server"],
            poweredBy = headerMap["x-powered-by"],
            cms = cmsLabel,
            cmsAdminPath = cmsAdmin,
            framework = tech.framework,
            pageBuilder = tech.pageBuilder,
            certIssuer = cert?.issuer,
            certSubject = cert?.subject,
            certValidFrom = cert?.validFrom,
            certValidTo = cert?.validTo,
            certSans = cert?.sans.orEmpty(),
            certSigAlg = cert?.sigAlg,
            dns = allDns,
            nameServers = nameServers,
            dnsHost = WebInfer.dnsHost(nameServers),
            registrar = who?.registrar,
            domainCreated = who?.created,
            domainUpdated = who?.updated,
            domainExpiry = who?.expiry,
            emailProvider = WebInfer.emailProvider(mxHosts),
            spf = spf, dmarc = dmarc, dkimHint = dkimHint,
            integrations = tech.integrations,
            socialLinks = tech.socialLinks,
            analyticsIds = tech.analyticsIds,
            fonts = tech.fonts,
            title = meta.title,
            description = meta.description,
            ogTitle = meta.ogTitle,
            ogImage = meta.ogImage,
            favicon = meta.favicon,
            canonicalLink = meta.canonical,
            viewport = meta.viewport,
            schemaTypes = meta.schemaTypes,
            businessName = meta.businessName,
            businessPhone = meta.businessPhone,
            businessAddress = meta.businessAddress,
            robotsFound = robotsFound,
            sitemapUrls = sitemapRefs.take(10),
            pageCount = pageCount,
            copyrightYear = meta.copyrightYear,
            redirectChain = redirectChain,
            brokenLinks = brokenLinks,
            sampledPages = sampledPages,
            presenceSearches = presence,
            seoScore = seo.score, seoGrade = seo.grade, seoChecks = seo.checks, seoCategories = seo.categories,
            aiScore = aiScore.score, aiGrade = aiScore.grade, aiChecks = aiScore.checks, aiCategories = aiScore.categories,
            a11yScore = a11y.score, a11yGrade = a11y.grade, a11yChecks = a11y.checks, a11yCategories = a11y.categories,
            attentionFlags = flags,
            versions = versions,
            securityHeaders = secHeaders,
            aiCrawlersBlocked = blockedAi,
            llmsTxt = llmsTxt,
            keyPages = signals.keyPages,
            contactEmails = signals.emails,
            contactPhones = signals.phones,
            responseMs = responseMs,
            htmlBytes = html.length.takeIf { it > 0 },
            scriptCount = signals.scriptCount,
            stylesheetCount = signals.stylesheetCount,
            scriptsInHead = signals.scriptsInHead,
            hostingLocation = hostingLocation,
            dnssec = dnssec,
            caa = caa,
            sslGrade = sslGrade,
            generatedAt = now,
            notes = notes,
        )
        if (allDns.isEmpty() && html.isBlank())
            Result.failure(IllegalStateException("Couldn't reach that domain — check the spelling or your connection."))
        else Result.success(profile)
    }

    /** Follows Location headers manually to reveal the redirect chain (http → https → www …). */
    private suspend fun traceRedirects(start: String): List<String> {
        val chain = ArrayList<String>()
        var url = start
        var hops = 0
        while (hops++ < 6) {
            chain.add(url)
            val r = runCatching { Http.get(url, followRedirects = false, timeoutMillis = 6_000, maxBytes = 2048) }.getOrNull() ?: break
            if (WebChecks.isRedirect(r.code)) {
                val loc = r.header("location") ?: break
                val next = runCatching { WebChecks.resolveRedirect(java.net.URI(url).toURL(), loc)?.toString() }.getOrNull() ?: break
                if (next == url || next in chain) break
                url = next
            } else break
        }
        return chain
    }

    /** GETs each sampled internal link and reports those returning 4xx/5xx. Network failures are skipped. */
    private suspend fun sampleBrokenLinks(links: List<String>): List<BrokenLink> = coroutineScope {
        val limiter = Semaphore(6)
        links.map { link ->
            async {
                limiter.withPermit {
                    val r = runCatching { Http.get(link, timeoutMillis = 5_000, maxBytes = 2048, followRedirects = true) }.getOrNull()
                    if (r != null && r.code >= 400) BrokenLink(link, r.code) else null
                }
            }
        }.awaitAll().filterNotNull()
    }

    /** Fetches a few inner pages and records title + word count, so scores reflect more than the homepage. */
    private suspend fun samplePages(internal: List<String>, canonicalUrl: String): List<PageSample> {
        val home = canonicalUrl.trimEnd('/')
        val candidates = internal.map { it.trimEnd('/') }.filter { it != home }.distinct().take(3)
        return coroutineScope {
            candidates.map { u ->
                async {
                    val r = runCatching { Http.get(u, timeoutMillis = 8_000, maxBytes = 400 * 1024) }.getOrNull()
                    val title = r?.body?.let { SiteSignatures.meta(it).title }
                    val words = r?.body?.let { SiteSignatures.pageSignals(it, u).wordCount } ?: 0
                    PageSample(u, title, words, r?.code ?: 0)
                }
            }.awaitAll()
        }
    }

    private fun readCert(host: String): CertData? = runCatching {
        val factory = SSLSocketFactory.getDefault() as SSLSocketFactory
        (factory.createSocket() as SSLSocket).use { socket ->
            socket.connect(InetSocketAddress(host, 443), 8_000)
            socket.soTimeout = 8_000
            socket.startHandshake()
            val x = socket.session.peerCertificates.firstOrNull() as? X509Certificate ?: return@use null
            val sans = runCatching { x.subjectAlternativeNames?.mapNotNull { it.getOrNull(1)?.toString() } }.getOrNull().orEmpty()
            CertData(
                issuer = dnField(x.issuerX500Principal.name, "O") ?: dnField(x.issuerX500Principal.name, "CN"),
                subject = dnField(x.subjectX500Principal.name, "CN"),
                validFrom = x.notBefore?.time,
                validTo = x.notAfter?.time,
                sigAlg = x.sigAlgName,
                sans = sans.take(25),
            )
        }
    }.getOrNull()

    private fun dnField(dn: String, key: String): String? =
        dn.split(',').map { it.trim() }.firstOrNull { it.startsWith("$key=", ignoreCase = true) }
            ?.substringAfter('=')?.trim()?.takeIf { it.isNotBlank() }
}
