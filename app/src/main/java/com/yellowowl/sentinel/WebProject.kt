package com.yellowowl.sentinel

import org.json.JSONArray
import org.json.JSONObject

/**
 * Saved web-intake projects, one per client domain, with a history of runs so you can re-open a past
 * report, watch the scores trend across a rebuild, and re-run on demand. Each run stores its scores and
 * the fully-rendered HTML report (a self-contained snapshot), so re-opening needs no re-fetch.
 *
 * Pure model + JSON codec; the Context-bound persistence lives in [WebProjectStore].
 */
data class IntakeRun(
    val at: Long,
    val seo: Int?, val ai: Int?, val a11y: Int?,
    val seoGrade: String?, val aiGrade: String?, val a11yGrade: String?,
    val flags: Int,
    val html: String,
    // Monitor snapshot — lets us diff cert / domain / DNS / IP between runs (all optional for old runs).
    val certValidTo: Long? = null,
    val certIssuer: String? = null,
    val domainExpiry: String? = null,
    val ip: String? = null,
    val nameServers: List<String> = emptyList(),
    val dnsSig: String? = null,
)

data class ClientProject(
    val domain: String,
    val label: String,
    val firstSeen: Long,
    val runs: List<IntakeRun>,
) {
    val latest: IntakeRun? get() = runs.maxByOrNull { it.at }
    val lastRun: Long get() = latest?.at ?: 0L
    val runCount: Int get() = runs.size
}

object WebProjectCodec {
    const val MAX_RUNS = 12

    fun runFromProfile(p: SiteProfile, html: String): IntakeRun = IntakeRun(
        at = p.generatedAt.takeIf { it > 0 } ?: System.currentTimeMillis(),
        seo = p.seoScore, ai = p.aiScore, a11y = p.a11yScore,
        seoGrade = p.seoGrade, aiGrade = p.aiGrade, a11yGrade = p.a11yGrade,
        flags = p.attentionFlags.size, html = html,
        certValidTo = p.certValidTo,
        certIssuer = p.certIssuer,
        domainExpiry = p.domainExpiry,
        ip = p.ip,
        nameServers = p.nameServers,
        dnsSig = dnsSignature(p.dns),
    )

    /** Stable fingerprint of the DNS record set, so a run-to-run change is a simple string comparison. */
    fun dnsSignature(dns: List<SiteDnsRecord>): String? {
        if (dns.isEmpty()) return null
        return dns.map { "${it.type}:${it.value}" }.sorted().joinToString("|").hashCode().toString()
    }

    fun encode(projects: List<ClientProject>): String {
        val arr = JSONArray()
        for (p in projects) {
            val runs = JSONArray()
            for (r in p.runs) {
                runs.put(
                    JSONObject().put("at", r.at)
                        .put("seo", r.seo ?: JSONObject.NULL).put("ai", r.ai ?: JSONObject.NULL).put("a11y", r.a11y ?: JSONObject.NULL)
                        .put("seoGrade", r.seoGrade ?: JSONObject.NULL).put("aiGrade", r.aiGrade ?: JSONObject.NULL).put("a11yGrade", r.a11yGrade ?: JSONObject.NULL)
                        .put("flags", r.flags).put("html", r.html)
                        .put("certValidTo", r.certValidTo ?: JSONObject.NULL).put("certIssuer", r.certIssuer ?: JSONObject.NULL)
                        .put("domainExpiry", r.domainExpiry ?: JSONObject.NULL).put("ip", r.ip ?: JSONObject.NULL)
                        .put("nameServers", JSONArray().apply { r.nameServers.forEach { put(it) } }).put("dnsSig", r.dnsSig ?: JSONObject.NULL)
                )
            }
            arr.put(JSONObject().put("domain", p.domain).put("label", p.label).put("firstSeen", p.firstSeen).put("runs", runs))
        }
        return JSONObject().put("version", 1).put("projects", arr).toString()
    }

    fun decode(json: String): List<ClientProject> {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return emptyList()
        val arr = root.optJSONArray("projects") ?: return emptyList()
        val out = ArrayList<ClientProject>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val domain = o.optString("domain")
            if (domain.isBlank()) continue
            val runsArr = o.optJSONArray("runs") ?: JSONArray()
            val runs = ArrayList<IntakeRun>(runsArr.length())
            for (j in 0 until runsArr.length()) {
                val r = runsArr.optJSONObject(j) ?: continue
                fun i2(k: String) = if (r.isNull(k)) null else r.optInt(k)
                fun s2(k: String) = r.optString(k).ifBlank { null }
                val ns = r.optJSONArray("nameServers")?.let { a -> (0 until a.length()).map { a.optString(it) }.filter { it.isNotBlank() } } ?: emptyList()
                runs.add(
                    IntakeRun(
                        at = r.optLong("at"),
                        seo = i2("seo"), ai = i2("ai"), a11y = i2("a11y"),
                        seoGrade = s2("seoGrade"), aiGrade = s2("aiGrade"), a11yGrade = s2("a11yGrade"),
                        flags = r.optInt("flags"), html = r.optString("html"),
                        certValidTo = if (r.isNull("certValidTo")) null else r.optLong("certValidTo"),
                        certIssuer = s2("certIssuer"), domainExpiry = s2("domainExpiry"), ip = s2("ip"),
                        nameServers = ns, dnsSig = s2("dnsSig"),
                    )
                )
            }
            out.add(ClientProject(domain, o.optString("label").ifBlank { domain }, o.optLong("firstSeen"), runs.sortedByDescending { it.at }))
        }
        return out.sortedByDescending { it.lastRun }
    }
}
