package com.yellowowl.sentinel

import kotlin.math.roundToInt

/**
 * Turns the scored intake into something a client can read: a plain-English executive summary and a
 * prioritized list of quick wins. Pure and deterministic — no I/O — so it is cheap to unit-test and is
 * reused by both the in-app report and the HTML/PDF/CSV/JSON exports.
 *
 * Quick wins are derived from the failing/half-credit checks that already drive the three scores, so
 * the advice is always consistent with the numbers. Each check label maps to a jargon-light action and
 * a one-line reason; wins are de-duplicated by action (a few checks overlap across SEO/AI/accessibility)
 * and ranked by points lost, so the costliest fixes float to the top.
 */
enum class WinImpact(val label: String) { HIGH("High impact"), MEDIUM("Medium impact"), LOW("Low impact") }

data class QuickWin(val title: String, val why: String, val impact: WinImpact)

object SiteSummary {

    /** Simple average of whichever of the three scores were computed. */
    fun overall(p: SiteProfile): Int? {
        val scores = listOfNotNull(p.seoScore, p.aiScore, p.a11yScore)
        return if (scores.isEmpty()) null else scores.sum().toDouble().div(scores.size).roundToInt()
    }

    private fun band(score: Int): String = when {
        score >= 85 -> "in strong shape"
        score >= 70 -> "in good shape, with room to improve"
        score >= 55 -> "a fair start that needs work"
        else -> "in rough shape and needs attention"
    }

    private data class Named(val plain: String, val score: Int?, val grade: String?)

    /** 2–4 plain sentences a client can read without any technical background. */
    fun executiveSummary(p: SiteProfile): List<String> {
        val out = ArrayList<String>()
        val site = p.businessName?.takeIf { it.isNotBlank() } ?: p.domain
        val ov = overall(p)

        // Lead with any genuinely urgent problem (security / invisibility), in client terms.
        val urgent = p.attentionFlags.firstOrNull { f ->
            f.contains("expired", true) || f.contains("noindex", true) ||
                f.contains("force HTTPS", true) || f.contains("blocks all crawlers", true)
        }
        if (urgent != null) out.add("Needs attention first: ${urgent.trimEnd('.')}.")

        if (ov != null) {
            out.add("Overall, $site is ${band(ov)}, scoring $ov out of 100 across search visibility, AI visibility and accessibility.")
            val areas = listOf(
                Named("search visibility", p.seoScore, p.seoGrade),
                Named("AI visibility", p.aiScore, p.aiGrade),
                Named("accessibility", p.a11yScore, p.a11yGrade),
            ).filter { it.score != null }
            val best = areas.maxByOrNull { it.score!! }
            val worst = areas.minByOrNull { it.score!! }
            if (best != null && worst != null && best.plain != worst.plain) {
                out.add("Its strongest area is ${best.plain} (${best.grade}); the weakest is ${worst.plain} (${worst.grade}), which is where the most gain is.")
            }
        } else {
            out.add("$site was captured, but the scores could not be computed for this run.")
        }

        val wins = quickWins(p)
        if (wins.isEmpty()) {
            out.add("No priority fixes stood out — the fundamentals are in place.")
        } else {
            val high = wins.count { it.impact == WinImpact.HIGH }
            val lead = wins.first()
            val headline = if (high > 0) "$high high-impact fix${if (high == 1) "" else "es"} to prioritize" else "${wins.size} improvement${if (wins.size == 1) "" else "s"} to consider"
            out.add("There ${if (high == 1) "is" else "are"} $headline. The biggest single win: ${lead.title.replaceFirstChar { it.lowercase() }}.")
        }
        return out
    }

    /** Prioritized, de-duplicated list of concrete fixes drawn from the failing/half-credit checks. */
    fun quickWins(p: SiteProfile, limit: Int = 8): List<QuickWin> {
        val all = p.seoChecks + p.aiChecks + p.a11yChecks
        // points lost per check: full weight on FAIL, half on WARN
        data class Scored(val win: QuickWin, val lost: Double, val fail: Boolean)
        val byAction = LinkedHashMap<String, Scored>()
        for (ch in all) {
            if (ch.status == CheckStatus.PASS) continue
            val advice = adviceFor(ch.label) ?: continue
            val lost = if (ch.status == CheckStatus.FAIL) ch.weight.toDouble() else ch.weight * 0.5
            val impact = when {
                lost >= 10 -> WinImpact.HIGH
                lost >= 5 -> WinImpact.MEDIUM
                else -> WinImpact.LOW
            }
            val win = QuickWin(advice.first, advice.second, impact)
            val prev = byAction[advice.first]
            // Merge overlaps (same action from several scores): keep the largest loss / worst status.
            if (prev == null || lost > prev.lost) {
                byAction[advice.first] = Scored(win.copy(impact = impact), lost, ch.status == CheckStatus.FAIL)
            }
        }
        return byAction.values
            .sortedWith(compareByDescending<Scored> { it.fail }.thenByDescending { it.lost })
            .take(limit)
            .map { it.win }
    }

    /** Maps a stable check label to (client-facing action, one-line reason). Null = not surfaced as a win. */
    private fun adviceFor(label: String): Pair<String, String>? = when (label) {
        "Title tag (30–60 chars)" ->
            "Tighten the page title to 30–60 characters" to "The title is the clickable headline in Google — too long gets cut off, too short wastes the space."
        "Meta description (70–160 chars)" ->
            "Write a 70–160 character meta description" to "This is the summary shown under your link in search results; a good one earns more clicks."
        "Exactly one H1", "Heading structure (one H1 + H2s)", "Semantic headings (H1 + H2s)" ->
            "Fix the heading structure (one clear H1, then H2s)" to "Clear headings tell search engines, AI and screen readers what the page is about."
        "Content depth (≥ 600 words)", "Content is server-rendered (readable)" ->
            "Add more real text content to the page" to "Thin pages rank poorly and give AI assistants little to quote; aim for substantial, readable copy."
        "Image alt coverage (≥ 90%)" ->
            "Add alt text to images" to "Alt text describes images for screen readers and helps image search — missing it fails accessibility too."
        "Structured data (schema.org)", "Structured data present" ->
            "Add structured data (schema.org markup)" to "This machine-readable markup is how Google rich results and AI answer engines understand your business."
        "Organization / business schema" ->
            "Add Organization/LocalBusiness schema" to "Lets search and AI tie the page to your business as a known entity — key for being cited and for local results."
        "FAQ / HowTo / Article schema" ->
            "Add FAQ, HowTo or Article schema where it fits" to "These formats are frequently surfaced in rich results and quoted by AI answer engines."
        "Entity links (schema sameAs)" ->
            "Link your official profiles with schema sameAs" to "Connecting your site to your verified social/business profiles strengthens how AI recognizes your brand."
        "Open Graph tags" ->
            "Add Open Graph tags for sharing" to "Controls the title, description and image shown when the site is shared on social media or chat."
        "Indexable (not noindex)" ->
            "Remove the noindex so the page can rank" to "The homepage is currently told not to appear in search results at all — this hides it from Google."
        "HTTPS enforced" ->
            "Force HTTPS (redirect http to https)" to "Visitors and search engines expect a secure connection; mixed access looks untrustworthy and hurts ranking."
        "HSTS header" ->
            "Enable the HSTS security header" to "Tells browsers to always use the secure version, closing a common downgrade attack."
        "Canonical link" ->
            "Add a canonical link tag" to "Tells search engines which URL is the 'real' one, avoiding duplicate-content confusion between www/non-www."
        "Mobile viewport" ->
            "Add a mobile viewport tag" to "Without it the site won't scale on phones — most visitors and Google's mobile-first index are mobile."
        "Language declared (<html lang>)" ->
            "Declare the page language (html lang)" to "Helps screen readers pronounce content correctly and tells search engines the audience."
        "XML sitemap" ->
            "Publish an XML sitemap" to "Gives search engines and AI crawlers a clean map of every page worth indexing."
        "robots.txt" ->
            "Add a robots.txt file" to "Guides crawlers on what to index and points them to your sitemap."
        "llms.txt present" ->
            "Add an llms.txt file" to "An emerging standard that tells AI assistants which content they may use — low effort, future-friendly."
        "Fast response (< 800 ms)" ->
            "Speed up the server response time" to "Slow first-byte times frustrate visitors and are a direct ranking and conversion drag."
        "Few render-blocking head scripts" ->
            "Reduce render-blocking scripts in the head" to "Too many scripts loading before content delays what the visitor actually sees."
        "Lean HTML payload" ->
            "Trim the page's HTML weight" to "Heavy pages load slowly on mobile data and hurt both experience and ranking."
        "Clear title + description" ->
            "Make sure both a title and description are set" to "These two lines are what both search engines and AI use to summarize the page."
        "Author / E-E-A-T signal" ->
            "Add clear authorship / about info" to "Signals of real people and expertise (E-E-A-T) increasingly influence trust in search and AI."
        "Allows AI crawlers" ->
            "Stop blocking AI crawlers in robots.txt" to "The site currently blocks assistants like ChatGPT or Perplexity, so it can't be cited by them."
        "Page has a title" ->
            "Give the page a title" to "Screen readers announce it first and it's the browser-tab and search headline."
        "Landmark regions (main / nav)" ->
            "Add landmark regions (main, nav)" to "Lets screen-reader users jump straight to the content or menu instead of reading everything."
        "Links have discernible text" ->
            "Give every link meaningful text" to "'Click here' and icon-only links leave screen-reader users with no idea where they lead."
        "Skip-to-content link" ->
            "Add a skip-to-content link" to "Lets keyboard and screen-reader users bypass the menu and go straight to the page content."
        "Zoom not disabled" ->
            "Allow pinch-zoom on mobile" to "Disabling zoom blocks low-vision users from enlarging text — a common accessibility failure."
        "Form inputs labeled" ->
            "Label every form field" to "Unlabeled inputs are unusable with a screen reader and confuse autofill."
        else -> null
    }
}
