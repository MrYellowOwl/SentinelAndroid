package com.yellowowl.sentinel

/**
 * Pure scoring for the web-developer intake: an SEO score and an "AI Visibility" score (how well the
 * site is positioned for AI answer engines / LLM crawlers), each a 0–100 with a letter grade and a
 * pass/fail checklist, plus the robots.txt AI-crawler analysis and the top-of-report attention flags.
 */
object SiteScore {
    data class Result(val score: Int, val grade: String, val checks: List<ScoreCheck>)

    fun grade(s: Int): String = when {
        s >= 90 -> "A"; s >= 80 -> "B"; s >= 70 -> "C"; s >= 55 -> "D"; else -> "F"
    }

    private fun result(checks: List<ScoreCheck>): Result {
        val s = if (checks.isEmpty()) 0 else checks.count { it.passed } * 100 / checks.size
        return Result(s, grade(s), checks)
    }

    fun seo(
        s: SiteSignatures.PageSignals,
        title: String?, description: String?, canonical: String?, viewport: String?,
        httpsEnforced: Boolean, schemaTypes: List<String>, favicon: String?,
        hasRobots: Boolean, hasSitemap: Boolean, hasAnalytics: Boolean,
    ): Result = result(listOf(
        ScoreCheck("Title present (10–65 chars)", title != null && title.trim().length in 10..65),
        ScoreCheck("Meta description (50–165 chars)", description != null && description.trim().length in 50..165),
        ScoreCheck("Exactly one H1", s.h1Count == 1),
        ScoreCheck("Canonical link", !canonical.isNullOrBlank()),
        ScoreCheck("Mobile viewport", !viewport.isNullOrBlank()),
        ScoreCheck("Language declared (<html lang>)", !s.htmlLang.isNullOrBlank()),
        ScoreCheck("HTTPS enforced", httpsEnforced),
        ScoreCheck("Structured data (schema.org)", schemaTypes.isNotEmpty()),
        ScoreCheck("Open Graph tags", s.hasOpenGraph),
        ScoreCheck("robots.txt", hasRobots),
        ScoreCheck("XML sitemap", hasSitemap),
        ScoreCheck("Favicon", !favicon.isNullOrBlank()),
        ScoreCheck("Image alt coverage ≥ 80%", s.imgCount == 0 || s.imgWithAlt * 100 / s.imgCount.coerceAtLeast(1) >= 80),
        ScoreCheck("Indexable (not noindex)", !s.noindex),
        ScoreCheck("Content depth (≥ 300 words)", s.wordCount >= 300),
        ScoreCheck("Analytics installed", hasAnalytics),
    ))

    fun ai(
        s: SiteSignatures.PageSignals,
        blockedAi: List<String>, starBlocksAll: Boolean, llmsTxt: Boolean,
        schemaTypes: List<String>, title: String?, description: String?, hasSitemap: Boolean,
    ): Result {
        val org = schemaTypes.any { it.contains("Organization", true) || it.contains("LocalBusiness", true) || it.equals("Person", true) }
        val faq = schemaTypes.any { it.equals("FAQPage", true) || it.equals("QAPage", true) || it.equals("HowTo", true) }
        return result(listOf(
            ScoreCheck("Allows AI crawlers", blockedAi.isEmpty() && !starBlocksAll),
            ScoreCheck("Content is server-rendered (readable)", s.wordCount >= 250),
            ScoreCheck("Structured data present", schemaTypes.isNotEmpty()),
            ScoreCheck("Organization / business schema", org),
            ScoreCheck("FAQ / HowTo schema", faq),
            ScoreCheck("Clear title + description", !title.isNullOrBlank() && !description.isNullOrBlank()),
            ScoreCheck("Open Graph tags", s.hasOpenGraph),
            ScoreCheck("XML sitemap", hasSitemap),
            ScoreCheck("Has an H1 heading", s.h1Count >= 1),
            ScoreCheck("llms.txt present", llmsTxt),
        ))
    }

    // --------------------------------------------------------------- robots.txt AI-crawler analysis

    /** AI/LLM crawler user-agents worth reporting on. */
    val aiCrawlerAgents = listOf(
        "GPTBot", "ChatGPT-User", "OAI-SearchBot", "ClaudeBot", "Claude-Web", "anthropic-ai",
        "PerplexityBot", "Google-Extended", "CCBot", "Bytespider", "Amazonbot", "Applebot-Extended",
    )

    /** Map of user-agent (lowercased) → its disallow values, honoring robots.txt group rules. */
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

    /** True when `User-agent: *` disallows the whole site. */
    fun starBlocksAll(robots: String): Boolean = blocksRoot(disallowMap(robots)["*"])

    /** AI crawlers effectively blocked (their own rule disallows /, or `*` does and they have no own rule). */
    fun blockedAiCrawlers(robots: String): List<String> {
        if (robots.isBlank()) return emptyList()
        val map = disallowMap(robots)
        val star = blocksRoot(map["*"])
        return aiCrawlerAgents.filter { bot ->
            val own = map[bot.lowercase()]
            if (own != null) blocksRoot(own) else star
        }
    }

    // --------------------------------------------------------------- attention flags

    fun attentionFlags(
        httpsEnforced: Boolean, certValidTo: Long?, sslWeak: Boolean,
        domainExpiryDays: Int?, blockedAi: List<String>, starBlocksAll: Boolean,
        title: String?, description: String?, h1Count: Int, noindex: Boolean,
        dmarc: Boolean, schemaTypes: List<String>, mixedContent: Boolean,
        copyrightYear: String?, currentYear: Int, now: Long,
    ): List<String> {
        val out = ArrayList<String>()
        if (!httpsEnforced) out.add("Site doesn't force HTTPS (http isn't redirected).")
        if (certValidTo != null) {
            val days = ((certValidTo - now) / 86_400_000L).toInt()
            if (days in 0..30) out.add("TLS certificate expires in $days day(s).")
            else if (days < 0) out.add("TLS certificate has expired.")
        }
        if (sslWeak) out.add("Weak or outdated TLS certificate.")
        if (domainExpiryDays != null && domainExpiryDays in 0..60) out.add("Domain registration expires in $domainExpiryDays day(s).")
        if (starBlocksAll) out.add("robots.txt blocks all crawlers (Disallow: /).")
        else if (blockedAi.isNotEmpty()) out.add("Blocks AI crawlers: ${blockedAi.joinToString(", ")} — invisible to those AI tools.")
        if (noindex) out.add("Homepage is set to noindex — it won't appear in search.")
        if (title.isNullOrBlank()) out.add("Missing <title>.")
        if (description.isNullOrBlank()) out.add("Missing meta description.")
        if (h1Count == 0) out.add("No H1 heading on the homepage.")
        if (!dmarc) out.add("No DMARC record — email spoofing isn't blocked.")
        if (schemaTypes.isEmpty()) out.add("No structured data (schema.org) — weaker for search and AI.")
        if (mixedContent) out.add("Mixed content — HTTP resources loaded on an HTTPS page.")
        copyrightYear?.toIntOrNull()?.let { if (it in 2000 until (currentYear - 2)) out.add("Footer copyright says $it — content may be stale.") }
        return out
    }
}
