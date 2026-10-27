package com.yellowowl.sentinel

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

/** Renders a [SiteProfile] to a polished, print-ready HTML report, plus CSV / JSON. Pure, unit-testable. */
object SiteReport {
    private fun date(ms: Long?): String? = ms?.let { SimpleDateFormat("yyyy-MM-dd", Locale.US).format(Date(it)) }
    private fun esc(s: String?): String = (s ?: "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    private fun scoreColor(s: Int): String = when { s >= 80 -> "#0a8f6e"; s >= 60 -> "#d97706"; else -> "#dc2626" }
    private fun statusColor(st: CheckStatus): String = when (st) { CheckStatus.PASS -> "#0a8f6e"; CheckStatus.WARN -> "#d97706"; CheckStatus.FAIL -> "#dc2626" }

    // ------------------------------------------------------------------- HTML (print-ready)

    fun toHtml(p: SiteProfile, appVersion: String): String {
        val sb = StringBuilder()
        fun row(label: String, value: String?) { if (!value.isNullOrBlank()) sb.append("<tr><th>${esc(label)}</th><td>${esc(value)}</td></tr>") }
        fun linkRow(label: String, url: String?) { if (!url.isNullOrBlank()) sb.append("<tr><th>${esc(label)}</th><td><a href=\"${esc(url)}\">${esc(url)}</a></td></tr>") }
        fun section(title: String, body: StringBuilder.() -> Unit) {
            val before = sb.length
            sb.append("<section><h2 class=\"sec\">${esc(title)}</h2><table>")
            val tableStart = sb.length
            sb.body()
            if (sb.length == tableStart) { sb.setLength(before); return }   // drop empty sections
            sb.append("</table></section>")
        }
        fun yn(b: Boolean) = if (b) "Yes" else "No"

        val generated = SimpleDateFormat("MMMM d, yyyy 'at' HH:mm", Locale.US).format(Date(p.generatedAt.takeIf { it > 0 } ?: System.currentTimeMillis()))

        sb.append("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">")
        sb.append("<title>Website intake — ${esc(p.domain)}</title><style>")
        sb.append(
            "@page{margin:16mm 13mm}*{box-sizing:border-box}" +
                "body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#14142b;font-size:13px;line-height:1.45;margin:0;background:#fff}" +
                ".wrap{max-width:860px;margin:0 auto;padding:22px}" +
                "header.rpt{border-bottom:3px solid #0ea5a5;padding-bottom:10px;margin-bottom:6px}" +
                "header.rpt h1{font-size:24px;margin:0;letter-spacing:-.3px}.meta{color:#6b7280;font-size:12px;margin-top:3px}" +
                ".scores{display:flex;gap:14px;margin:18px 0}" +
                ".sc{flex:1;border:1px solid #e5e7eb;border-radius:10px;padding:14px}" +
                ".sc h3{margin:0 0 4px;font-size:11px;text-transform:uppercase;letter-spacing:.7px;color:#6b7280}" +
                ".sc .num{font-size:40px;font-weight:800;line-height:1}.sc .num small{font-size:16px;font-weight:700;margin-left:6px}" +
                ".bar{height:7px;background:#eef0f3;border-radius:4px;overflow:hidden;margin-top:3px}.bar>i{display:block;height:100%}" +
                ".cat{display:flex;align-items:center;gap:8px;font-size:10.5px;color:#4b5563;margin-top:6px}.cat .lbl{width:118px}.cat .bar{flex:1}.cat .val{width:38px;text-align:right}" +
                ".attn{border-left:4px solid #dc2626;background:#fef2f2;padding:10px 14px;border-radius:0 8px 8px 0;margin:16px 0}" +
                ".attn h2{color:#b91c1c;margin:0 0 6px;font-size:13px;text-transform:uppercase;letter-spacing:.5px}.attn ul{margin:0;padding-left:18px}.attn li{color:#7f1d1d;margin:2px 0}" +
                "h2.sec{font-size:12px;text-transform:uppercase;letter-spacing:.7px;color:#0a8f6e;border-bottom:1px solid #e5e7eb;padding-bottom:4px;margin:20px 0 6px}" +
                "table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:5px 8px;font-size:12.5px;border-bottom:1px solid #f1f2f4;vertical-align:top;word-break:break-word}" +
                "th{width:180px;color:#4b5563;font-weight:600}td{color:#14142b}tr:nth-child(even) td,tr:nth-child(even) th{background:#fafbfc}a{color:#0b61d6;text-decoration:none}" +
                ".chk{padding:3px 0;font-size:12px;display:flex;align-items:center;gap:7px;border:0}.dot{width:9px;height:9px;border-radius:50%;flex:none}" +
                ".cglabel{font-size:10.5px;text-transform:uppercase;letter-spacing:.5px;color:#9ca3af;margin:8px 0 2px;font-weight:700}" +
                "section{page-break-inside:avoid}footer{margin-top:26px;border-top:1px solid #e5e7eb;padding-top:8px;color:#9ca3af;font-size:11px}" +
                "@media print{body{-webkit-print-color-adjust:exact;print-color-adjust:exact}}"
        )
        sb.append("</style></head><body><div class=\"wrap\">")

        sb.append("<header class=\"rpt\"><h1>Website intake</h1><div class=\"meta\">${esc(p.domain)} · $generated · Sentinel $appVersion</div></header>")

        // Scorecard
        if (p.seoScore != null || p.aiScore != null) {
            sb.append("<div class=\"scores\">")
            fun scoreCard(name: String, score: Int?, grade: String?, cats: List<ScoreCategory>) {
                if (score == null) return
                val col = scoreColor(score)
                sb.append("<div class=\"sc\"><h3>$name</h3><div class=\"num\" style=\"color:$col\">$score<small>/100 · ${esc(grade)}</small></div>")
                cats.forEach { c ->
                    val pct = if (c.possible == 0) 0 else c.earned * 100 / c.possible
                    sb.append("<div class=\"cat\"><span class=\"lbl\">${esc(c.name)}</span><span class=\"bar\"><i style=\"width:$pct%;background:${scoreColor(pct)}\"></i></span><span class=\"val\">${c.earned}/${c.possible}</span></div>")
                }
                sb.append("</div>")
            }
            scoreCard("SEO", p.seoScore, p.seoGrade, p.seoCategories)
            scoreCard("AI Visibility", p.aiScore, p.aiGrade, p.aiCategories)
            scoreCard("Accessibility", p.a11yScore, p.a11yGrade, p.a11yCategories)
            sb.append("</div>")
        }

        // Attention
        if (p.attentionFlags.isNotEmpty()) {
            sb.append("<div class=\"attn\"><h2>Needs attention (${p.attentionFlags.size})</h2><ul>")
            p.attentionFlags.forEach { sb.append("<li>${esc(it)}</li>") }
            sb.append("</ul></div>")
        }

        section("Snapshot") {
            row("Domain", p.domain); row("Canonical URL", p.canonicalUrl)
            row("Prefers", if (p.usesWww) "www" else "apex (no www)"); row("Forces HTTPS", yn(p.httpsRedirect))
            row("Final URL", p.finalUrl); row("HTTP status", p.statusCode?.toString())
            row("IP address", p.ip); row("Hosting", p.hostingProvider); row("Location", p.hostingLocation)
            row("ASN / org", p.asn); row("CDN", p.cdn)
        }
        section("Performance") {
            row("Response time", p.responseMs?.let { "$it ms" }); row("HTML size", p.htmlBytes?.let { "${it / 1024} KB" })
            row("Scripts", p.scriptCount?.toString()); row("Stylesheets", p.stylesheetCount?.toString())
            row("Render-blocking head scripts", p.scriptsInHead?.toString()); row("Server header", p.serverHeader); row("X-Powered-By", p.poweredBy)
        }
        section("Domain & registrar") {
            row("Registrar", p.registrar); row("Created", p.domainCreated); row("Updated", p.domainUpdated); row("Expires", p.domainExpiry)
            row("DNS host", p.dnsHost); row("Name servers", p.nameServers.joinToString(", "))
        }
        section("Certificate") {
            row("Issuer", p.certIssuer); row("Subject", p.certSubject)
            row("Valid from", date(p.certValidFrom)); row("Expires", date(p.certValidTo))
            row("Signature", p.certSigAlg); row("SANs", p.certSans.joinToString(", "))
        }
        section("DNS security & email") {
            row("DNSSEC", if (p.dnssec) "Enabled" else "Not enabled"); row("CAA record", if (p.caa) "Present" else "None"); row("SSL grade", p.sslGrade)
            row("Email provider", p.emailProvider); row("SPF", yn(p.spf)); row("DMARC", yn(p.dmarc)); row("DKIM (detected)", yn(p.dkimHint))
        }
        section("Security headers") { p.securityHeaders.forEach { row(it.key, if (it.value) "Present" else "Missing") } }
        section("Platform & stack") {
            row("CMS / platform", p.cms); row("Admin login", p.cmsAdminPath); row("Framework", p.framework); row("Page builder", p.pageBuilder); row("Fonts", p.fonts.joinToString(", "))
        }
        section("Stack versions") { p.versions.forEach { row(it.key, it.value) } }
        section("Third-party integrations") { p.integrations.forEach { row(it.category, it.name) } }
        section("IDs to migrate") { p.analyticsIds.forEach { row(it.kind, it.value) } }
        section("Content & SEO") {
            row("Title", p.title); row("Meta description", p.description); row("Canonical link", p.canonicalLink)
            row("Viewport", p.viewport); row("Schema types", p.schemaTypes.joinToString(", ")); row("Copyright year", p.copyrightYear)
            row("robots.txt", yn(p.robotsFound)); row("Pages (sitemap)", p.pageCount?.toString())
            row("Blocks AI crawlers", p.aiCrawlersBlocked.joinToString(", ")); row("llms.txt", if (p.llmsTxt) "Present" else "Absent")
        }
        section("Business") { row("Name", p.businessName); row("Phone", p.businessPhone); row("Address", p.businessAddress) }
        section("Contacts on page") { p.contactEmails.forEach { row("Email", it) }; p.contactPhones.forEach { row("Phone", it) } }
        section("Key pages") { p.keyPages.forEach { linkRow(it.label, it.url) } }
        if (p.redirectChain.size > 1) section("Redirect chain") { row("Hops", p.redirectChain.joinToString(" → ")) }
        section("Broken links") { p.brokenLinks.forEach { row("HTTP ${it.status}", it.url) } }
        section("Sampled pages") { p.sampledPages.forEach { row(it.title ?: it.url, "${it.words} words · HTTP ${it.status}") } }
        section("Social") { p.socialLinks.forEach { linkRow(it.label, it.url) } }
        section("Online presence (search)") { p.presenceSearches.forEach { linkRow(it.label, it.url) } }
        section("DNS records") { p.dns.forEach { row(it.type, it.value) } }

        // Score checklists (appendix)
        fun checklist(name: String, checks: List<ScoreCheck>) {
            if (checks.isEmpty()) return
            sb.append("<section><h2 class=\"sec\">$name checklist</h2>")
            checks.groupBy { it.category }.forEach { (cat, cs) ->
                sb.append("<div class=\"cglabel\">${esc(cat)}</div>")
                cs.forEach { c ->
                    sb.append("<div class=\"chk\"><span class=\"dot\" style=\"background:${statusColor(c.status)}\"></span>${esc(c.label)} — <b style=\"color:${statusColor(c.status)}\">${c.status.name}</b></div>")
                }
            }
            sb.append("</section>")
        }
        checklist("SEO", p.seoChecks)
        checklist("AI Visibility", p.aiChecks)
        checklist("Accessibility", p.a11yChecks)

        p.notes.forEach { sb.append("<p style=\"color:#9a6700;font-size:11px\">⚠ ${esc(it)}</p>") }
        sb.append("<footer>Generated by Sentinel $appVersion · read-only passive reconnaissance · scores are a transparent heuristic, not a substitute for a full audit.</footer>")
        sb.append("</div></body></html>")
        return sb.toString()
    }

    // ------------------------------------------------------------------- CSV

    fun toCsv(p: SiteProfile): String {
        fun q(s: String?) = "\"" + (s ?: "").replace("\"", "\"\"") + "\""
        val sb = StringBuilder("Field,Value\n")
        fun r(k: String, v: String?) { if (!v.isNullOrBlank()) sb.append("${q(k)},${q(v)}\n") }
        r("Domain", p.domain); r("Canonical URL", p.canonicalUrl); r("Prefers", if (p.usesWww) "www" else "apex")
        r("Forces HTTPS", if (p.httpsRedirect) "Yes" else "No"); r("Final URL", p.finalUrl); r("HTTP status", p.statusCode?.toString())
        r("SEO score", p.seoScore?.let { "$it (${p.seoGrade})" })
        r("AI Visibility score", p.aiScore?.let { "$it (${p.aiGrade})" })
        r("Accessibility score", p.a11yScore?.let { "$it (${p.a11yGrade})" })
        p.seoCategories.forEach { r("SEO · ${it.name}", "${it.earned}/${it.possible}") }
        p.aiCategories.forEach { r("AI · ${it.name}", "${it.earned}/${it.possible}") }
        p.a11yCategories.forEach { r("A11y · ${it.name}", "${it.earned}/${it.possible}") }
        r("Blocks AI crawlers", p.aiCrawlersBlocked.joinToString("; ").ifBlank { null }); r("llms.txt", if (p.llmsTxt) "Present" else "Absent")
        p.attentionFlags.forEachIndexed { i, f -> r("Attention ${i + 1}", f) }
        r("IP", p.ip); r("Hosting", p.hostingProvider); r("Location", p.hostingLocation); r("ASN", p.asn); r("CDN", p.cdn)
        r("Response time", p.responseMs?.let { "$it ms" }); r("HTML size", p.htmlBytes?.let { "${it / 1024} KB" })
        r("Scripts", p.scriptCount?.toString()); r("Stylesheets", p.stylesheetCount?.toString())
        r("Registrar", p.registrar); r("Created", p.domainCreated); r("Updated", p.domainUpdated); r("Expires", p.domainExpiry)
        r("DNS host", p.dnsHost); r("Name servers", p.nameServers.joinToString("; "))
        r("Cert issuer", p.certIssuer); r("Cert expires", date(p.certValidTo)); r("Cert signature", p.certSigAlg)
        r("DNSSEC", if (p.dnssec) "Enabled" else "No"); r("CAA", if (p.caa) "Present" else "No"); r("SSL grade", p.sslGrade)
        r("Email provider", p.emailProvider); r("SPF", if (p.spf) "Yes" else "No"); r("DMARC", if (p.dmarc) "Yes" else "No"); r("DKIM", if (p.dkimHint) "Yes" else "No")
        r("CMS", p.cms); r("Admin login", p.cmsAdminPath); r("Framework", p.framework); r("Page builder", p.pageBuilder); r("Fonts", p.fonts.joinToString("; "))
        p.integrations.forEach { r("Integration: ${it.category}", it.name) }
        p.analyticsIds.forEach { r("ID: ${it.kind}", it.value) }
        r("Title", p.title); r("Description", p.description); r("Schema types", p.schemaTypes.joinToString("; ")); r("Copyright", p.copyrightYear)
        r("Business name", p.businessName); r("Business phone", p.businessPhone); r("Business address", p.businessAddress)
        r("robots.txt", if (p.robotsFound) "Yes" else "No"); r("Pages (sitemap)", p.pageCount?.toString())
        p.contactEmails.forEach { r("Contact email", it) }; p.contactPhones.forEach { r("Contact phone", it) }
        p.keyPages.forEach { r("Key page: ${it.label}", it.url) }
        if (p.redirectChain.size > 1) r("Redirect chain", p.redirectChain.joinToString(" -> "))
        p.brokenLinks.forEach { r("Broken link (HTTP ${it.status})", it.url) }
        p.sampledPages.forEach { r("Sampled page", "${it.title ?: it.url} — ${it.words} words — HTTP ${it.status}") }
        p.socialLinks.forEach { r("Social: ${it.label}", it.url) }
        p.versions.forEach { r("Version: ${it.key}", it.value) }
        p.securityHeaders.forEach { r("Security header: ${it.key}", if (it.value) "Present" else "Missing") }
        p.seoChecks.forEach { r("SEO check: ${it.label}", it.status.name) }
        p.aiChecks.forEach { r("AI check: ${it.label}", it.status.name) }
        p.a11yChecks.forEach { r("A11y check: ${it.label}", it.status.name) }
        p.dns.forEach { r("DNS ${it.type}", it.value) }
        return sb.toString()
    }

    // ------------------------------------------------------------------- JSON

    fun toJson(p: SiteProfile, appVersion: String): String {
        fun arr(items: List<String>) = JSONArray().apply { items.forEach { put(it) } }
        fun checksJson(checks: List<ScoreCheck>) = JSONArray().apply {
            checks.forEach { put(JSONObject().put("label", it.label).put("category", it.category).put("status", it.status.name).put("weight", it.weight)) }
        }
        fun catsJson(cats: List<ScoreCategory>) = JSONArray().apply {
            cats.forEach { put(JSONObject().put("name", it.name).put("earned", it.earned).put("possible", it.possible)) }
        }
        val o = JSONObject()
        o.put("tool", "Sentinel $appVersion").put("generatedAt", p.generatedAt)
        o.put("domain", p.domain).put("canonicalUrl", p.canonicalUrl).put("usesWww", p.usesWww)
            .put("forcesHttps", p.httpsRedirect).put("finalUrl", p.finalUrl).put("statusCode", p.statusCode ?: JSONObject.NULL)
        o.put("scores", JSONObject()
            .put("seo", JSONObject().put("score", p.seoScore ?: JSONObject.NULL).put("grade", p.seoGrade ?: JSONObject.NULL).put("categories", catsJson(p.seoCategories)).put("checks", checksJson(p.seoChecks)))
            .put("ai", JSONObject().put("score", p.aiScore ?: JSONObject.NULL).put("grade", p.aiGrade ?: JSONObject.NULL).put("categories", catsJson(p.aiCategories)).put("checks", checksJson(p.aiChecks)))
            .put("accessibility", JSONObject().put("score", p.a11yScore ?: JSONObject.NULL).put("grade", p.a11yGrade ?: JSONObject.NULL).put("categories", catsJson(p.a11yCategories)).put("checks", checksJson(p.a11yChecks)))
            .put("blocksAiCrawlers", arr(p.aiCrawlersBlocked)).put("llmsTxt", p.llmsTxt))
        o.put("versions", JSONObject().apply { p.versions.forEach { put(it.key, it.value) } })
        o.put("securityHeaders", JSONObject().apply { p.securityHeaders.forEach { put(it.key, it.value) } })
        o.put("attention", arr(p.attentionFlags))
        o.put("hosting", JSONObject().put("ip", p.ip ?: JSONObject.NULL).put("provider", p.hostingProvider ?: JSONObject.NULL)
            .put("location", p.hostingLocation ?: JSONObject.NULL).put("asn", p.asn ?: JSONObject.NULL).put("cdn", p.cdn ?: JSONObject.NULL)
            .put("server", p.serverHeader ?: JSONObject.NULL).put("poweredBy", p.poweredBy ?: JSONObject.NULL))
        o.put("performance", JSONObject().put("responseMs", p.responseMs ?: JSONObject.NULL).put("htmlBytes", p.htmlBytes ?: JSONObject.NULL)
            .put("scripts", p.scriptCount ?: JSONObject.NULL).put("stylesheets", p.stylesheetCount ?: JSONObject.NULL).put("headScripts", p.scriptsInHead ?: JSONObject.NULL))
        o.put("domainReg", JSONObject().put("registrar", p.registrar ?: JSONObject.NULL).put("created", p.domainCreated ?: JSONObject.NULL)
            .put("updated", p.domainUpdated ?: JSONObject.NULL).put("expires", p.domainExpiry ?: JSONObject.NULL)
            .put("dnsHost", p.dnsHost ?: JSONObject.NULL).put("nameServers", arr(p.nameServers)))
        o.put("certificate", JSONObject().put("issuer", p.certIssuer ?: JSONObject.NULL).put("subject", p.certSubject ?: JSONObject.NULL)
            .put("validFrom", p.certValidFrom ?: JSONObject.NULL).put("validTo", p.certValidTo ?: JSONObject.NULL)
            .put("signature", p.certSigAlg ?: JSONObject.NULL).put("sans", arr(p.certSans)))
        o.put("dnsSecurity", JSONObject().put("dnssec", p.dnssec).put("caa", p.caa).put("sslGrade", p.sslGrade ?: JSONObject.NULL))
        o.put("email", JSONObject().put("provider", p.emailProvider ?: JSONObject.NULL).put("spf", p.spf).put("dmarc", p.dmarc).put("dkim", p.dkimHint))
        o.put("stack", JSONObject().put("cms", p.cms ?: JSONObject.NULL).put("adminPath", p.cmsAdminPath ?: JSONObject.NULL)
            .put("framework", p.framework ?: JSONObject.NULL).put("pageBuilder", p.pageBuilder ?: JSONObject.NULL).put("fonts", arr(p.fonts)))
        o.put("integrations", JSONArray().apply { p.integrations.forEach { put(JSONObject().put("name", it.name).put("category", it.category)) } })
        o.put("ids", JSONArray().apply { p.analyticsIds.forEach { put(JSONObject().put("kind", it.kind).put("value", it.value)) } })
        o.put("seo", JSONObject().put("title", p.title ?: JSONObject.NULL).put("description", p.description ?: JSONObject.NULL)
            .put("canonical", p.canonicalLink ?: JSONObject.NULL).put("viewport", p.viewport ?: JSONObject.NULL)
            .put("schemaTypes", arr(p.schemaTypes)).put("copyright", p.copyrightYear ?: JSONObject.NULL))
        o.put("business", JSONObject().put("name", p.businessName ?: JSONObject.NULL).put("phone", p.businessPhone ?: JSONObject.NULL).put("address", p.businessAddress ?: JSONObject.NULL))
        o.put("structure", JSONObject().put("robots", p.robotsFound).put("pages", p.pageCount ?: JSONObject.NULL).put("sitemaps", arr(p.sitemapUrls)))
        o.put("redirectChain", arr(p.redirectChain))
        o.put("brokenLinks", JSONArray().apply { p.brokenLinks.forEach { put(JSONObject().put("url", it.url).put("status", it.status)) } })
        o.put("sampledPages", JSONArray().apply { p.sampledPages.forEach { put(JSONObject().put("url", it.url).put("title", it.title ?: JSONObject.NULL).put("words", it.words).put("status", it.status)) } })
        o.put("contacts", JSONObject().put("emails", arr(p.contactEmails)).put("phones", arr(p.contactPhones)))
        o.put("keyPages", JSONArray().apply { p.keyPages.forEach { put(JSONObject().put("label", it.label).put("url", it.url)) } })
        o.put("social", JSONArray().apply { p.socialLinks.forEach { put(JSONObject().put("platform", it.label).put("url", it.url)) } })
        o.put("dns", JSONArray().apply { p.dns.forEach { put(JSONObject().put("type", it.type).put("value", it.value)) } })
        o.put("notes", arr(p.notes))
        return o.toString(2)
    }
}
