package com.yellowowl.sentinel

import org.json.JSONArray

/**
 * Passive subdomain discovery from Certificate Transparency logs. Read-only: it reads public
 * certificate records, touching none of the target's own infrastructure. Pure parsing, tested.
 *
 * Primary source is crt.sh; [certSpotterUrl]/[parseCertSpotter] provide a fallback because crt.sh
 * is frequently slow or briefly down. Parsing tolerates truncated or non-JSON bodies (crt.sh can
 * return a huge array that gets capped mid-stream, or an HTML error page) by salvaging host names
 * with a regex instead of failing outright.
 */
object CertSearch {
    fun crtShUrl(domain: String): String = "https://crt.sh/?q=%25.${domain.trim().lowercase()}&output=json"

    /** Certspotter's free issuances endpoint (rate-limited without a key, but a useful fallback). */
    fun certSpotterUrl(domain: String): String =
        "https://api.certspotter.com/v1/issuances?domain=${domain.trim().lowercase()}" +
            "&include_subdomains=true&expand=dns_names"

    /** Extracts unique hostnames under [domain] from a crt.sh JSON response (or a truncated one). */
    fun parseSubdomains(json: String, domain: String): List<String> {
        val names = runCatching { crtShNamesFromJson(json) }.getOrNull()
            ?.takeIf { it.isNotEmpty() }
            ?: salvageNames(json)   // truncated array / HTML error page / format drift
        return filterAndSort(names, domain)
    }

    /** Extracts unique hostnames under [domain] from a Certspotter issuances response. */
    fun parseCertSpotter(json: String, domain: String): List<String> {
        val names = runCatching {
            val arr = JSONArray(json)
            buildList {
                for (i in 0 until arr.length()) {
                    val dns = arr.optJSONObject(i)?.optJSONArray("dns_names") ?: continue
                    for (j in 0 until dns.length()) add(dns.optString(j))
                }
            }
        }.getOrNull()?.takeIf { it.isNotEmpty() } ?: salvageNames(json)
        return filterAndSort(names, domain)
    }

    // ---- internals ----

    private fun crtShNamesFromJson(json: String): List<String> {
        val arr = JSONArray(json)
        return buildList {
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                // name_value can carry several names separated by newlines; common_name is a single one.
                (o.optString("name_value") + "\n" + o.optString("common_name"))
                    .split('\n', ',').forEach { add(it) }
            }
        }
    }

    // Pulls name_value / common_name / dns_names string contents out of raw (possibly truncated) text.
    private val hostFieldRe =
        Regex(""""(?:name_value|common_name|dns_names)"\s*:\s*(?:"((?:[^"\\]|\\.)*)"|\[([^\]]*)\])""")
    private val quotedRe = Regex(""""((?:[^"\\]|\\.)*)"""")

    private fun salvageNames(text: String): List<String> = buildList {
        for (m in hostFieldRe.findAll(text)) {
            val str = m.groupValues[1]
            val arr = m.groupValues[2]
            if (str.isNotEmpty()) {
                unescape(str).split('\n', ',').forEach { add(it) }
            } else if (arr.isNotEmpty()) {
                for (q in quotedRe.findAll(arr)) add(unescape(q.groupValues[1]))
            }
        }
    }

    private fun unescape(s: String): String =
        s.replace("\\n", "\n").replace("\\/", "/").replace("\\\"", "\"").replace("\\\\", "\\")

    /** True if any resolved address is an RFC 1918 private IP (subdomain pointing at internal infrastructure). */
    fun hasInternalAddress(ips: List<String>): Boolean =
        ips.any { Ipv4.parse(it.trim())?.let(Ipv4::isPrivate) == true }

    /** One output line for a subdomain: "name → ip[, ip]  [INTERNAL]", or just the name when it didn't resolve. */
    fun describeResolved(name: String, ips: List<String>): String {
        val addrs = ips.map { it.trim() }.filter { it.isNotEmpty() }
        if (addrs.isEmpty()) return name
        val tag = if (hasInternalAddress(addrs)) "  [INTERNAL]" else ""
        return "$name → ${addrs.joinToString(", ")}$tag"
    }

    private fun filterAndSort(names: List<String>, domain: String): List<String> {
        val base = domain.trim().lowercase().trimEnd('.')
        val found = ArrayList<String>()
        for (raw in names) {
            val name = raw.trim().lowercase().removePrefix("*.").trimEnd('.')
            if (name.isEmpty()) continue
            if (name == base || name.endsWith(".$base")) found.add(name)
        }
        return sortHosts(found)
    }

    /** Dedupe and order host names by depth then alphabetically, so the apex and registrable domain lead. */
    fun sortHosts(names: Collection<String>): List<String> =
        LinkedHashSet(names).sortedWith(compareBy({ it.count { c -> c == '.' } }, { it }))
}
