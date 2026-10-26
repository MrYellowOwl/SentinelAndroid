package com.yellowowl.sentinel

/**
 * The web-developer "site intake" profile — a comprehensive snapshot of an existing website for a
 * rebuild/takeover: who hosts it, who runs DNS, the registrar and dates, the certificate, the CMS and
 * stack, every third-party integration, the SEO/meta and business info, and the site structure.
 *
 * This is the data model; collection lives in [SiteIntake] and rendering/export in [SiteReport].
 * The small record types here are shared with the pure detectors ([SiteSignatures], [WhoisParse]).
 */

data class SiteDnsRecord(val type: String, val value: String)
data class SiteTech(val name: String, val category: String)   // "Google Analytics 4" / "Analytics"
data class SiteLink(val label: String, val url: String)
data class SiteId(val kind: String, val value: String)        // "GA4", "G-XXXX"

data class SiteProfile(
    val input: String,
    val domain: String,
    val canonicalUrl: String,
    val usesWww: Boolean,
    val httpsRedirect: Boolean,
    val finalUrl: String,
    val statusCode: Int?,
    val redirectChain: List<String> = emptyList(),

    // Hosting / network
    val ip: String? = null,
    val hostingProvider: String? = null,
    val asn: String? = null,
    val cdn: String? = null,
    val serverHeader: String? = null,
    val poweredBy: String? = null,

    // Platform / stack
    val cms: String? = null,
    val cmsAdminPath: String? = null,
    val framework: String? = null,
    val pageBuilder: String? = null,

    // Certificate
    val certIssuer: String? = null,
    val certSubject: String? = null,
    val certValidFrom: Long? = null,
    val certValidTo: Long? = null,
    val certSans: List<String> = emptyList(),
    val certSigAlg: String? = null,

    // DNS
    val dns: List<SiteDnsRecord> = emptyList(),
    val nameServers: List<String> = emptyList(),
    val dnsHost: String? = null,            // who runs DNS, inferred from NS hostnames

    // Registrar / domain
    val registrar: String? = null,
    val domainCreated: String? = null,
    val domainUpdated: String? = null,
    val domainExpiry: String? = null,

    // Email
    val emailProvider: String? = null,      // inferred from MX
    val spf: Boolean = false,
    val dmarc: Boolean = false,
    val dkimHint: Boolean = false,

    // Integrations / stack from the page
    val integrations: List<SiteTech> = emptyList(),
    val socialLinks: List<SiteLink> = emptyList(),
    val analyticsIds: List<SiteId> = emptyList(),
    val fonts: List<String> = emptyList(),

    // SEO / meta / business
    val title: String? = null,
    val description: String? = null,
    val ogTitle: String? = null,
    val ogImage: String? = null,
    val favicon: String? = null,
    val canonicalLink: String? = null,
    val viewport: String? = null,
    val schemaTypes: List<String> = emptyList(),
    val businessName: String? = null,
    val businessPhone: String? = null,
    val businessAddress: String? = null,

    // Structure
    val robotsFound: Boolean = false,
    val sitemapUrls: List<String> = emptyList(),
    val pageCount: Int? = null,
    val copyrightYear: String? = null,

    // Presence (search links — detection of actual profiles needs APIs we don't require)
    val presenceSearches: List<SiteLink> = emptyList(),

    val generatedAt: Long = 0L,
    val notes: List<String> = emptyList(),   // per-source caveats / failures
)
