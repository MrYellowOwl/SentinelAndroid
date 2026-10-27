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
enum class CheckStatus { PASS, WARN, FAIL }
/** One weighted scoring criterion. WARN earns half credit. [category] groups it within a score. */
data class ScoreCheck(val label: String, val category: String, val status: CheckStatus, val weight: Int)
data class ScoreCategory(val name: String, val earned: Int, val possible: Int)

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

    // Scores
    val seoScore: Int? = null,
    val seoGrade: String? = null,
    val seoChecks: List<ScoreCheck> = emptyList(),
    val seoCategories: List<ScoreCategory> = emptyList(),
    val aiScore: Int? = null,
    val aiGrade: String? = null,
    val aiChecks: List<ScoreCheck> = emptyList(),
    val aiCategories: List<ScoreCategory> = emptyList(),
    val attentionFlags: List<String> = emptyList(),

    // AI crawlers / structure signals
    val aiCrawlersBlocked: List<String> = emptyList(),
    val llmsTxt: Boolean = false,

    // Key pages & contacts
    val keyPages: List<SiteLink> = emptyList(),
    val contactEmails: List<String> = emptyList(),
    val contactPhones: List<String> = emptyList(),

    // Performance snapshot
    val responseMs: Long? = null,
    val htmlBytes: Int? = null,
    val scriptCount: Int? = null,
    val stylesheetCount: Int? = null,
    val scriptsInHead: Int? = null,

    // Hosting location & DNS security
    val hostingLocation: String? = null,
    val dnssec: Boolean = false,
    val caa: Boolean = false,
    val sslGrade: String? = null,

    val generatedAt: Long = 0L,
    val notes: List<String> = emptyList(),   // per-source caveats / failures
)
