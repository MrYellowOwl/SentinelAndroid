package com.yellowowl.sentinel

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

/** Renders a [SiteProfile] to HTML / CSV / JSON for export. Pure and unit-testable. */
object SiteReport {
    private fun date(ms: Long?): String? = ms?.let { SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(it)) }

    private fun esc(s: String?): String = (s ?: "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    fun toHtml(p: SiteProfile, appVersion: String): String {
        val sb = StringBuilder()
        fun row(label: String, value: String?) {
            if (!value.isNullOrBlank()) sb.append("<tr><th>${esc(label)}</th><td>${esc(value)}</td></tr>")
        }
        fun section(title: String, body: StringBuilder.() -> Unit) {
            sb.append("<h2>${esc(title)}</h2><table>"); sb.body(); sb.append("</table>")
        }
        fun yn(b: Boolean) = if (b) "Yes" else "No"

        val generated = SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(p.generatedAt.takeIf { it > 0 } ?: System.currentTimeMillis()))
        sb.append(
            "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">" +
                "<title>Site intake — ${esc(p.domain)}</title><style>" +
                "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:24px;color:#111;background:#fff;max-width:900px}" +
                "h1{font-size:22px;margin:0 0 2px}h2{font-size:15px;margin:22px 0 6px;color:#0a6}" +
                ".sub{color:#666;font-size:13px;margin-bottom:8px}" +
                "table{border-collapse:collapse;width:100%;margin-bottom:4px}" +
                "th,td{text-align:left;vertical-align:top;padding:5px 8px;border-bottom:1px solid #eee;font-size:13px}" +
                "th{width:190px;color:#555;font-weight:600}td{color:#111;word-break:break-word}" +
                "a{color:#06c;text-decoration:none}.note{color:#a60;font-size:12px}" +
                "</style></head><body>"
        )
        sb.append("<h1>Website intake — ${esc(p.domain)}</h1>")
        sb.append("<div class=\"sub\">Generated $generated · Sentinel $appVersion</div>")

        if (p.seoScore != null || p.aiScore != null) section("Scores") {
            row("SEO score", p.seoScore?.let { "$it / 100 (${p.seoGrade})" })
            row("AI Visibility score", p.aiScore?.let { "$it / 100 (${p.aiGrade})" })
            row("Blocks AI crawlers", p.aiCrawlersBlocked.joinToString(", ").ifBlank { null })
            row("llms.txt", if (p.llmsTxt) "Present" else "Absent")
        }
        if (p.attentionFlags.isNotEmpty()) {
            sb.append("<h2>Needs attention</h2><ul>")
            p.attentionFlags.forEach { sb.append("<li class=\"note\">${esc(it)}</li>") }
            sb.append("</ul>")
        }

        section("Overview") {
            row("Domain", p.domain)
            row("Canonical URL", p.canonicalUrl)
            row("Prefers", if (p.usesWww) "www" else "apex (no www)")
            row("Forces HTTPS", yn(p.httpsRedirect))
            row("Final URL", p.finalUrl)
            row("HTTP status", p.statusCode?.toString())
        }
        section("Hosting & network") {
            row("IP address", p.ip)
            row("Hosting provider", p.hostingProvider)
            row("Location", p.hostingLocation)
            row("ASN / org", p.asn)
            row("CDN", p.cdn)
            row("Server header", p.serverHeader)
            row("X-Powered-By", p.poweredBy)
        }
        section("Performance") {
            row("Response time", p.responseMs?.let { "$it ms" })
            row("HTML size", p.htmlBytes?.let { "${it / 1024} KB" })
            row("Scripts", p.scriptCount?.toString())
            row("Stylesheets", p.stylesheetCount?.toString())
            row("Render-blocking head scripts", p.scriptsInHead?.toString())
        }
        section("DNS security") {
            row("DNSSEC", if (p.dnssec) "Enabled" else "Not enabled")
            row("CAA record", if (p.caa) "Present" else "None")
            row("SSL grade", p.sslGrade)
        }
        section("Domain & registrar") {
            row("Registrar", p.registrar)
            row("Created", p.domainCreated)
            row("Updated", p.domainUpdated)
            row("Expires", p.domainExpiry)
            row("DNS host", p.dnsHost)
            row("Name servers", p.nameServers.joinToString(", "))
        }
        section("Certificate") {
            row("Issuer", p.certIssuer)
            row("Subject", p.certSubject)
            row("Valid from", date(p.certValidFrom))
            row("Expires", date(p.certValidTo))
            row("Signature", p.certSigAlg)
            row("SANs", p.certSans.joinToString(", "))
        }
        section("Email") {
            row("Email provider", p.emailProvider)
            row("SPF", yn(p.spf)); row("DMARC", yn(p.dmarc)); row("DKIM (detected)", yn(p.dkimHint))
        }
        section("Platform & stack") {
            row("CMS / platform", p.cms)
            row("Admin login", p.cmsAdminPath)
            row("Framework", p.framework)
            row("Page builder", p.pageBuilder)
            row("Fonts", p.fonts.joinToString(", "))
        }
        if (p.integrations.isNotEmpty()) section("Third-party integrations") {
            p.integrations.forEach { row(it.category, it.name) }
        }
        if (p.analyticsIds.isNotEmpty()) section("IDs to migrate") {
            p.analyticsIds.forEach { row(it.kind, it.value) }
        }
        section("SEO & meta") {
            row("Title", p.title); row("Description", p.description)
            row("OG image", p.ogImage); row("Canonical link", p.canonicalLink)
            row("Viewport", p.viewport); row("Favicon", p.favicon)
            row("Schema types", p.schemaTypes.joinToString(", "))
            row("Copyright year", p.copyrightYear)
        }
        if (p.businessName != null || p.businessPhone != null || p.businessAddress != null) section("Business") {
            row("Name", p.businessName); row("Phone", p.businessPhone); row("Address", p.businessAddress)
        }
        if (p.contactEmails.isNotEmpty() || p.contactPhones.isNotEmpty()) section("Contacts on page") {
            p.contactEmails.forEach { row("Email", it) }
            p.contactPhones.forEach { row("Phone", it) }
        }
        if (p.keyPages.isNotEmpty()) section("Key pages") {
            p.keyPages.forEach { sb.append("<tr><th>${esc(it.label)}</th><td><a href=\"${esc(it.url)}\">${esc(it.url)}</a></td></tr>") }
        }
        section("Structure") {
            row("robots.txt", yn(p.robotsFound))
            row("Pages (sitemap)", p.pageCount?.toString())
            if (p.sitemapUrls.isNotEmpty()) sb.append("<tr><th>Sitemaps</th><td>${p.sitemapUrls.joinToString("<br>") { "<a href=\"${esc(it)}\">${esc(it)}</a>" }}</td></tr>")
        }
        if (p.socialLinks.isNotEmpty()) section("Social") {
            p.socialLinks.forEach { sb.append("<tr><th>${esc(it.label)}</th><td><a href=\"${esc(it.url)}\">${esc(it.url)}</a></td></tr>") }
        }
        section("DNS records") {
            p.dns.forEach { sb.append("<tr><th>${esc(it.type)}</th><td>${esc(it.value)}</td></tr>") }
        }
        if (p.presenceSearches.isNotEmpty()) section("Online presence (search)") {
            p.presenceSearches.forEach { sb.append("<tr><th>${esc(it.label)}</th><td><a href=\"${esc(it.url)}\">${esc(it.url)}</a></td></tr>") }
        }
        p.notes.forEach { sb.append("<p class=\"note\">⚠ ${esc(it)}</p>") }
        sb.append("</body></html>")
        return sb.toString()
    }

    fun toCsv(p: SiteProfile): String {
        fun q(s: String?) = "\"" + (s ?: "").replace("\"", "\"\"") + "\""
        val sb = StringBuilder("Field,Value\n")
        fun r(k: String, v: String?) { if (!v.isNullOrBlank()) sb.append("${q(k)},${q(v)}\n") }
        r("Domain", p.domain); r("Canonical URL", p.canonicalUrl); r("Prefers", if (p.usesWww) "www" else "apex")
        r("Forces HTTPS", if (p.httpsRedirect) "Yes" else "No"); r("Final URL", p.finalUrl); r("HTTP status", p.statusCode?.toString())
        r("SEO score", p.seoScore?.let { "$it (${p.seoGrade})" })
        r("AI Visibility score", p.aiScore?.let { "$it (${p.aiGrade})" })
        r("Blocks AI crawlers", p.aiCrawlersBlocked.joinToString("; ").ifBlank { null })
        r("llms.txt", if (p.llmsTxt) "Present" else "Absent")
        p.attentionFlags.forEachIndexed { i, f -> r("Attention ${i + 1}", f) }
        r("IP", p.ip); r("Hosting", p.hostingProvider); r("Location", p.hostingLocation); r("ASN", p.asn); r("CDN", p.cdn)
        r("Response time", p.responseMs?.let { "$it ms" }); r("HTML size", p.htmlBytes?.let { "${it / 1024} KB" })
        r("Scripts", p.scriptCount?.toString()); r("Stylesheets", p.stylesheetCount?.toString())
        r("DNSSEC", if (p.dnssec) "Enabled" else "No"); r("CAA", if (p.caa) "Present" else "No"); r("SSL grade", p.sslGrade)
        p.contactEmails.forEach { r("Contact email", it) }; p.contactPhones.forEach { r("Contact phone", it) }
        p.keyPages.forEach { r("Key page: ${it.label}", it.url) }
        r("Server", p.serverHeader); r("X-Powered-By", p.poweredBy)
        r("Registrar", p.registrar); r("Created", p.domainCreated); r("Updated", p.domainUpdated); r("Expires", p.domainExpiry)
        r("DNS host", p.dnsHost); r("Name servers", p.nameServers.joinToString("; "))
        r("Cert issuer", p.certIssuer); r("Cert subject", p.certSubject)
        r("Cert valid from", date(p.certValidFrom)); r("Cert expires", date(p.certValidTo)); r("Cert signature", p.certSigAlg)
        r("Email provider", p.emailProvider); r("SPF", if (p.spf) "Yes" else "No"); r("DMARC", if (p.dmarc) "Yes" else "No"); r("DKIM", if (p.dkimHint) "Yes" else "No")
        r("CMS", p.cms); r("Admin login", p.cmsAdminPath); r("Framework", p.framework); r("Page builder", p.pageBuilder); r("Fonts", p.fonts.joinToString("; "))
        p.integrations.forEach { r("Integration: ${it.category}", it.name) }
        p.analyticsIds.forEach { r("ID: ${it.kind}", it.value) }
        r("Title", p.title); r("Description", p.description); r("Viewport", p.viewport); r("Canonical link", p.canonicalLink)
        r("Schema types", p.schemaTypes.joinToString("; ")); r("Copyright", p.copyrightYear)
        r("Business name", p.businessName); r("Business phone", p.businessPhone); r("Business address", p.businessAddress)
        r("robots.txt", if (p.robotsFound) "Yes" else "No"); r("Pages (sitemap)", p.pageCount?.toString())
        p.socialLinks.forEach { r("Social: ${it.label}", it.url) }
        p.dns.forEach { r("DNS ${it.type}", it.value) }
        return sb.toString()
    }

    fun toJson(p: SiteProfile, appVersion: String): String {
        fun arr(items: List<String>) = JSONArray().apply { items.forEach { put(it) } }
        val o = JSONObject()
        o.put("tool", "Sentinel $appVersion").put("generatedAt", p.generatedAt)
        o.put("domain", p.domain).put("canonicalUrl", p.canonicalUrl).put("usesWww", p.usesWww)
            .put("forcesHttps", p.httpsRedirect).put("finalUrl", p.finalUrl).put("statusCode", p.statusCode ?: JSONObject.NULL)
        o.put("scores", JSONObject().put("seo", p.seoScore ?: JSONObject.NULL).put("seoGrade", p.seoGrade ?: JSONObject.NULL)
            .put("aiVisibility", p.aiScore ?: JSONObject.NULL).put("aiGrade", p.aiGrade ?: JSONObject.NULL)
            .put("blocksAiCrawlers", arr(p.aiCrawlersBlocked)).put("llmsTxt", p.llmsTxt))
        o.put("attention", arr(p.attentionFlags))
        o.put("hosting", JSONObject().put("ip", p.ip ?: JSONObject.NULL).put("provider", p.hostingProvider ?: JSONObject.NULL)
            .put("location", p.hostingLocation ?: JSONObject.NULL)
            .put("asn", p.asn ?: JSONObject.NULL).put("cdn", p.cdn ?: JSONObject.NULL)
            .put("server", p.serverHeader ?: JSONObject.NULL).put("poweredBy", p.poweredBy ?: JSONObject.NULL))
        o.put("performance", JSONObject().put("responseMs", p.responseMs ?: JSONObject.NULL).put("htmlBytes", p.htmlBytes ?: JSONObject.NULL)
            .put("scripts", p.scriptCount ?: JSONObject.NULL).put("stylesheets", p.stylesheetCount ?: JSONObject.NULL).put("headScripts", p.scriptsInHead ?: JSONObject.NULL))
        o.put("dnsSecurity", JSONObject().put("dnssec", p.dnssec).put("caa", p.caa).put("sslGrade", p.sslGrade ?: JSONObject.NULL))
        o.put("contacts", JSONObject().put("emails", arr(p.contactEmails)).put("phones", arr(p.contactPhones)))
        o.put("keyPages", JSONArray().apply { p.keyPages.forEach { put(JSONObject().put("label", it.label).put("url", it.url)) } })
        o.put("domainReg", JSONObject().put("registrar", p.registrar ?: JSONObject.NULL).put("created", p.domainCreated ?: JSONObject.NULL)
            .put("updated", p.domainUpdated ?: JSONObject.NULL).put("expires", p.domainExpiry ?: JSONObject.NULL)
            .put("dnsHost", p.dnsHost ?: JSONObject.NULL).put("nameServers", arr(p.nameServers)))
        o.put("certificate", JSONObject().put("issuer", p.certIssuer ?: JSONObject.NULL).put("subject", p.certSubject ?: JSONObject.NULL)
            .put("validFrom", p.certValidFrom ?: JSONObject.NULL).put("validTo", p.certValidTo ?: JSONObject.NULL)
            .put("signature", p.certSigAlg ?: JSONObject.NULL).put("sans", arr(p.certSans)))
        o.put("email", JSONObject().put("provider", p.emailProvider ?: JSONObject.NULL).put("spf", p.spf).put("dmarc", p.dmarc).put("dkim", p.dkimHint))
        o.put("stack", JSONObject().put("cms", p.cms ?: JSONObject.NULL).put("adminPath", p.cmsAdminPath ?: JSONObject.NULL)
            .put("framework", p.framework ?: JSONObject.NULL).put("pageBuilder", p.pageBuilder ?: JSONObject.NULL).put("fonts", arr(p.fonts)))
        o.put("integrations", JSONArray().apply { p.integrations.forEach { put(JSONObject().put("name", it.name).put("category", it.category)) } })
        o.put("ids", JSONArray().apply { p.analyticsIds.forEach { put(JSONObject().put("kind", it.kind).put("value", it.value)) } })
        o.put("seo", JSONObject().put("title", p.title ?: JSONObject.NULL).put("description", p.description ?: JSONObject.NULL)
            .put("ogImage", p.ogImage ?: JSONObject.NULL).put("canonical", p.canonicalLink ?: JSONObject.NULL)
            .put("viewport", p.viewport ?: JSONObject.NULL).put("favicon", p.favicon ?: JSONObject.NULL)
            .put("schemaTypes", arr(p.schemaTypes)).put("copyright", p.copyrightYear ?: JSONObject.NULL))
        o.put("business", JSONObject().put("name", p.businessName ?: JSONObject.NULL).put("phone", p.businessPhone ?: JSONObject.NULL).put("address", p.businessAddress ?: JSONObject.NULL))
        o.put("structure", JSONObject().put("robots", p.robotsFound).put("pages", p.pageCount ?: JSONObject.NULL).put("sitemaps", arr(p.sitemapUrls)))
        o.put("social", JSONArray().apply { p.socialLinks.forEach { put(JSONObject().put("platform", it.label).put("url", it.url)) } })
        o.put("dns", JSONArray().apply { p.dns.forEach { put(JSONObject().put("type", it.type).put("value", it.value)) } })
        o.put("presenceSearches", JSONArray().apply { p.presenceSearches.forEach { put(JSONObject().put("label", it.label).put("url", it.url)) } })
        o.put("notes", arr(p.notes))
        return o.toString(2)
    }
}
