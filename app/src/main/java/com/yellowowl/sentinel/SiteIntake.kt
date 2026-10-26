package com.yellowowl.sentinel

import java.net.InetSocketAddress
import java.net.URLEncoder
import java.security.cert.X509Certificate
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
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
        val primary = fetch("https://$apex/") ?: fetch("https://www.$apex/") ?: fetch(url.toString())
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
        if (ip != null) {
            val info = runCatching {
                Http.get("http://ip-api.com/json/$ip?fields=status,message,query,isp,org,as,city,country", timeoutMillis = 8_000)
                    ?.body?.let { IpExposure.parseInfo(it) }
            }.getOrNull()
            asn = info?.asn
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

        val cmsLabel = tech.cms ?: meta.generator?.substringBefore(' ')?.takeIf { it.isNotBlank() }
        val profile = SiteProfile(
            input = input,
            domain = apex,
            canonicalUrl = canonicalUrl,
            usesWww = canonicalHost.startsWith("www."),
            httpsRedirect = httpsRedirect,
            finalUrl = finalUrl?.toString() ?: canonicalUrl,
            statusCode = primary?.code,
            redirectChain = emptyList(),
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
            presenceSearches = presence,
            generatedAt = System.currentTimeMillis(),
            notes = notes,
        )
        if (allDns.isEmpty() && html.isBlank())
            Result.failure(IllegalStateException("Couldn't reach that domain — check the spelling or your connection."))
        else Result.success(profile)
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
