package com.yellowowl.sentinel

import kotlin.math.roundToInt

/**
 * Rigorous, weighted scoring for the web-developer intake. Each criterion carries a weight and a
 * three-state result (PASS = full credit, WARN = half credit, FAIL = none); the score is the weighted
 * percentage earned, graded on a strict curve, and grouped into categories so you can see where a site
 * wins or loses. The SEO rubric follows the universally-checked technical/content/performance signals;
 * the AI-Visibility rubric follows what makes a site citable by AI answer engines (crawler access,
 * server-rendered content, structured data / entity markup).
 */
object SiteScore {
    data class Result(val score: Int, val grade: String, val checks: List<ScoreCheck>, val categories: List<ScoreCategory>)

    fun grade(s: Int): String = when {
        s >= 90 -> "A"; s >= 80 -> "B"; s >= 70 -> "C"; s >= 60 -> "D"; else -> "F"
    }

    private fun earned(c: ScoreCheck): Double = when (c.status) {
        CheckStatus.PASS -> c.weight.toDouble()
        CheckStatus.WARN -> c.weight * 0.5
        CheckStatus.FAIL -> 0.0
    }

    private fun build(checks: List<ScoreCheck>): Result {
        val possible = checks.sumOf { it.weight }
        val got = checks.sumOf { earned(it) }
        val score = if (possible == 0) 0 else (got / possible * 100).roundToInt()
        val cats = checks.groupBy { it.category }.map { (name, cs) ->
            ScoreCategory(name, cs.sumOf { earned(it) }.roundToInt(), cs.sumOf { it.weight })
        }
        return Result(score, grade(score), checks, cats)
    }

    private fun tri(ok: Boolean) = if (ok) CheckStatus.PASS else CheckStatus.FAIL

    // ------------------------------------------------------------------- SEO (weighted)

    fun seo(
        s: SiteSignatures.PageSignals,
        title: String?, description: String?, canonical: String?, viewport: String?,
        httpsEnforced: Boolean, hsts: Boolean, compression: Boolean,
        schemaTypes: List<String>, favicon: String?,
        hasRobots: Boolean, hasSitemap: Boolean, hasAnalytics: Boolean,
        responseMs: Long?, htmlBytes: Int?,
    ): Result {
        val c = ArrayList<ScoreCheck>()
        fun add(label: String, cat: String, status: CheckStatus, weight: Int) = c.add(ScoreCheck(label, cat, status, weight))

        val t = title?.trim()
        add("Title tag (30–60 chars)", "Content", when {
            t.isNullOrBlank() -> CheckStatus.FAIL
            t.length in 30..60 -> CheckStatus.PASS
            else -> CheckStatus.WARN
        }, 10)
        val d = description?.trim()
        add("Meta description (70–160 chars)", "Content", when {
            d.isNullOrBlank() -> CheckStatus.FAIL
            d.length in 70..160 -> CheckStatus.PASS
            else -> CheckStatus.WARN
        }, 8)
        add("Exactly one H1", "Content", when (s.h1Count) { 1 -> CheckStatus.PASS; 0 -> CheckStatus.FAIL; else -> CheckStatus.WARN }, 6)
        add("Content depth (≥ 600 words)", "Content", when { s.wordCount >= 600 -> CheckStatus.PASS; s.wordCount >= 300 -> CheckStatus.WARN; else -> CheckStatus.FAIL }, 7)
        add("Image alt coverage (≥ 90%)", "Content", when {
            s.imgCount == 0 -> CheckStatus.PASS
            s.imgWithAlt * 100 / s.imgCount >= 90 -> CheckStatus.PASS
            s.imgWithAlt * 100 / s.imgCount >= 60 -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }, 5)
        add("Structured data (schema.org)", "Content", tri(schemaTypes.isNotEmpty()), 8)
        add("Open Graph tags", "Content", tri(s.hasOpenGraph), 4)

        add("Indexable (not noindex)", "Technical", tri(!s.noindex), 12)
        add("HTTPS enforced", "Technical", tri(httpsEnforced), 10)
        add("HSTS header", "Technical", tri(hsts), 4)
        add("Canonical link", "Technical", tri(!canonical.isNullOrBlank()), 5)
        add("Mobile viewport", "Technical", tri(!viewport.isNullOrBlank()), 8)
        add("Language declared (<html lang>)", "Technical", tri(!s.htmlLang.isNullOrBlank()), 3)
        add("XML sitemap", "Technical", tri(hasSitemap), 6)
        add("robots.txt", "Technical", tri(hasRobots), 3)
        add("Favicon", "Technical", tri(!favicon.isNullOrBlank()), 2)

        add("Fast response (< 800 ms)", "Performance", when {
            responseMs == null -> CheckStatus.WARN
            responseMs < 800 -> CheckStatus.PASS
            responseMs < 2000 -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }, 6)
        // The HTTP client transparently decompresses and may strip Content-Encoding, so absence is
        // unconfirmed (half credit) rather than a hard fail.
        add("Compression enabled", "Performance", if (compression) CheckStatus.PASS else CheckStatus.WARN, 4)
        add("Few render-blocking head scripts", "Performance", when {
            s.scriptsInHead <= 2 -> CheckStatus.PASS
            s.scriptsInHead <= 5 -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }, 4)
        add("Lean HTML payload", "Performance", when {
            htmlBytes == null -> CheckStatus.WARN
            htmlBytes < 300 * 1024 -> CheckStatus.PASS
            htmlBytes < 1024 * 1024 -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }, 3)
        add("Analytics installed", "Performance", tri(hasAnalytics), 2)

        return build(c)
    }

    // ------------------------------------------------------------------- AI Visibility (weighted)

    private val majorAiAgents = listOf("GPTBot", "OAI-SearchBot", "ClaudeBot", "PerplexityBot", "Google-Extended")

    fun ai(
        s: SiteSignatures.PageSignals,
        blockedAi: List<String>, starBlocksAll: Boolean, llmsTxt: Boolean,
        schemaTypes: List<String>, title: String?, description: String?,
        canonical: String?, hasSitemap: Boolean,
    ): Result {
        val c = ArrayList<ScoreCheck>()
        fun add(label: String, cat: String, status: CheckStatus, weight: Int) = c.add(ScoreCheck(label, cat, status, weight))

        val blockedMajor = blockedAi.filter { b -> majorAiAgents.any { it.equals(b, true) } }
        add("Allows AI crawlers", "Access", when {
            starBlocksAll || blockedMajor.isNotEmpty() -> CheckStatus.FAIL
            blockedAi.isNotEmpty() -> CheckStatus.WARN
            else -> CheckStatus.PASS
        }, 20)
        add("Content is server-rendered (readable)", "Access", when {
            s.wordCount >= 500 -> CheckStatus.PASS
            s.wordCount >= 200 -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }, 15)
        add("XML sitemap", "Access", tri(hasSitemap), 6)
        add("llms.txt present", "Access", tri(llmsTxt), 5)
        add("Canonical link", "Access", tri(!canonical.isNullOrBlank()), 3)

        add("Structured data present", "Structure & entity", tri(schemaTypes.isNotEmpty()), 12)
        val entity = schemaTypes.any { it.contains("Organization", true) || it.contains("LocalBusiness", true) || it.equals("Person", true) }
        add("Organization / business schema", "Structure & entity", tri(entity), 10)
        val qa = schemaTypes.any { it.equals("FAQPage", true) || it.equals("QAPage", true) || it.equals("HowTo", true) || it.contains("Article", true) }
        add("FAQ / HowTo / Article schema", "Structure & entity", tri(qa), 8)
        add("Entity links (schema sameAs)", "Structure & entity", tri(s.hasSameAs), 4)
        add("Semantic headings (H1 + H2s)", "Structure & entity", when {
            s.h1Count >= 1 && s.h2Count >= 2 -> CheckStatus.PASS
            s.h1Count >= 1 -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }, 6)

        add("Clear title + description", "Content clarity", when {
            !title.isNullOrBlank() && !description.isNullOrBlank() -> CheckStatus.PASS
            !title.isNullOrBlank() || !description.isNullOrBlank() -> CheckStatus.WARN
            else -> CheckStatus.FAIL
        }, 8)
        add("Open Graph tags", "Content clarity", tri(s.hasOpenGraph), 5)
        add("Author / E-E-A-T signal", "Content clarity", tri(s.hasAuthor), 4)

        return build(c)
    }

    // ------------------------------------------------------------------- robots.txt AI-crawler analysis

    val aiCrawlerAgents = listOf(
        "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-Web", "anthropic-ai",
        "PerplexityBot", "Google-Extended", "CCBot", "Bytespider", "Amazonbot", "Applebot-Extended",
    )

    private fun disallowMap(robots: String): Map<String, List<String>> {
        val map = HashMap<String, MutableList<String>>()
        var current = ArrayList<String>()
        var afterRules = false
        for (raw in robots.lines()) {
            val line = raw.substringBefore('#').trim()
            val i = line.indexOf(':'); if (i <= 0) continue
            val key = line.substring(0, i).trim().lowercase()
            val value = line.substring(i + 1).trim()
            when (key) {
                "user-agent" -> {
                    if (afterRules) { current = ArrayList(); afterRules = false }
                    current.add(value.lowercase())
                }
                "disallow" -> { afterRules = true; for (a in current) map.getOrPut(a) { ArrayList() }.add(value) }
                "allow" -> afterRules = true
            }
        }
        return map
    }

    private fun blocksRoot(disallows: List<String>?): Boolean = disallows?.any { it == "/" } == true

    fun starBlocksAll(robots: String): Boolean = blocksRoot(disallowMap(robots)["*"])

    fun blockedAiCrawlers(robots: String): List<String> {
        if (robots.isBlank()) return emptyList()
        val map = disallowMap(robots)
        val star = blocksRoot(map["*"])
        return aiCrawlerAgents.filter { bot ->
            val own = map[bot.lowercase()]
            if (own != null) blocksRoot(own) else star
        }
    }

    // ------------------------------------------------------------------- attention flags

    fun attentionFlags(
        httpsEnforced: Boolean, hsts: Boolean, compression: Boolean, certValidTo: Long?, sslWeak: Boolean,
        domainExpiryDays: Int?, blockedAi: List<String>, starBlocksAll: Boolean,
        title: String?, description: String?, h1Count: Int, noindex: Boolean,
        dmarc: Boolean, schemaTypes: List<String>, mixedContent: Boolean, responseMs: Long?,
        copyrightYear: String?, currentYear: Int, now: Long,
    ): List<String> {
        val out = ArrayList<String>()
        if (noindex) out.add("Homepage is set to noindex — it won't appear in search.")
        if (starBlocksAll) out.add("robots.txt blocks all crawlers (Disallow: /).")
        else if (blockedAi.isNotEmpty()) out.add("Blocks AI crawlers: ${blockedAi.joinToString(", ")} — invisible to those AI tools.")
        if (!httpsEnforced) out.add("Site doesn't force HTTPS (http isn't redirected).")
        if (mixedContent) out.add("Mixed content — HTTP resources loaded on an HTTPS page.")
        if (certValidTo != null) {
            val days = ((certValidTo - now) / 86_400_000L).toInt()
            if (days < 0) out.add("TLS certificate has expired.")
            else if (days <= 30) out.add("TLS certificate expires in $days day(s).")
        }
        if (sslWeak) out.add("Weak or outdated TLS certificate.")
        if (domainExpiryDays != null && domainExpiryDays in 0..60) out.add("Domain registration expires in $domainExpiryDays day(s).")
        if (title.isNullOrBlank()) out.add("Missing <title>.")
        if (description.isNullOrBlank()) out.add("Missing meta description.")
        if (h1Count == 0) out.add("No H1 heading on the homepage.")
        if (schemaTypes.isEmpty()) out.add("No structured data (schema.org) — weaker for search and AI.")
        if (!dmarc) out.add("No DMARC record — email spoofing isn't blocked.")
        if (!hsts) out.add("No HSTS header — HTTPS isn't enforced at the browser level.")
        if (responseMs != null && responseMs >= 2000) out.add("Slow server response (${responseMs} ms).")
        copyrightYear?.toIntOrNull()?.let { if (it in 2000 until (currentYear - 2)) out.add("Footer copyright says $it — content may be stale.") }
        return out
    }
}
