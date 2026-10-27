package com.yellowowl.sentinel

import java.net.URLEncoder
import kotlin.math.roundToInt
import org.json.JSONObject

/**
 * Google PageSpeed Insights (Lighthouse) integration — real Core Web Vitals instead of our homespun
 * response-time heuristic. Opt-in: only runs when the user supplies a PSI API key (keyless PSI is
 * heavily rate-limited and would slow every audit), and it is display-only so the carefully-tuned
 * score model is untouched.
 *
 * This object is pure: [endpoint] builds the request URL and [parse] reads the lab metrics out of the
 * response. The network call itself lives in [SiteIntake]. Values are reported as lab data (mobile).
 */
object PageSpeed {
    data class Cwv(
        val performance: Int?,   // 0–100
        val lcpMs: Int?,
        val cls: Double?,
        val inpMs: Int?,
        val fcpMs: Int?,
        val tbtMs: Int?,
    ) {
        val isEmpty: Boolean get() = performance == null && lcpMs == null && cls == null && inpMs == null && fcpMs == null && tbtMs == null
    }

    fun endpoint(url: String, key: String?, strategy: String = "mobile"): String {
        val u = URLEncoder.encode(url, "UTF-8")
        val base = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=$u&strategy=$strategy&category=performance"
        return if (!key.isNullOrBlank()) "$base&key=${URLEncoder.encode(key, "UTF-8")}" else base
    }

    /** Pulls the performance score and the key lab metrics out of a PSI v5 response. Null if unusable. */
    fun parse(json: String): Cwv? {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val lh = root.optJSONObject("lighthouseResult") ?: return null

        val perf = lh.optJSONObject("categories")?.optJSONObject("performance")
            ?.let { if (it.isNull("score")) null else (it.optDouble("score") * 100).roundToInt() }

        val audits = lh.optJSONObject("audits")
        fun ms(id: String): Int? {
            val a = audits?.optJSONObject(id) ?: return null
            if (a.isNull("numericValue")) return null
            return a.optDouble("numericValue").roundToInt()
        }
        fun raw(id: String): Double? {
            val a = audits?.optJSONObject(id) ?: return null
            if (a.isNull("numericValue")) return null
            return a.optDouble("numericValue")
        }

        val inp = ms("interaction-to-next-paint") ?: ms("experimental-interaction-to-next-paint")
        val cwv = Cwv(
            performance = perf,
            lcpMs = ms("largest-contentful-paint"),
            cls = raw("cumulative-layout-shift")?.let { (it * 1000).roundToInt() / 1000.0 },
            inpMs = inp,
            fcpMs = ms("first-contentful-paint"),
            tbtMs = ms("total-blocking-time"),
        )
        return if (cwv.isEmpty) null else cwv
    }

    // Rating helpers (Google CWV thresholds) — used for color/labeling in the report.
    fun lcpRating(ms: Int): String = when { ms <= 2500 -> "Good"; ms <= 4000 -> "Needs work"; else -> "Poor" }
    fun clsRating(v: Double): String = when { v <= 0.1 -> "Good"; v <= 0.25 -> "Needs work"; else -> "Poor" }
    fun inpRating(ms: Int): String = when { ms <= 200 -> "Good"; ms <= 500 -> "Needs work"; else -> "Poor" }
}
