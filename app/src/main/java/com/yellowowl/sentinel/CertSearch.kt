package com.yellowowl.sentinel

import org.json.JSONArray

/**
 * Passive subdomain discovery from Certificate Transparency logs (crt.sh). Read-only: it reads
 * public certificate records, touching none of the target's infrastructure. Pure parsing, tested.
 */
object CertSearch {
    fun crtShUrl(domain: String): String = "https://crt.sh/?q=%25.${domain.trim().lowercase()}&output=json"

    /** Extracts unique hostnames under [domain] from a crt.sh JSON response. */
    fun parseSubdomains(json: String, domain: String): List<String> {
        val base = domain.trim().lowercase().trimEnd('.')
        val found = LinkedHashSet<String>()
        try {
            val arr = JSONArray(json)
            for (i in 0 until arr.length()) {
                val o = arr.optJSONObject(i) ?: continue
                // name_value can carry several names separated by newlines; common_name is a single one.
                val names = (o.optString("name_value") + "\n" + o.optString("common_name"))
                    .split('\n', ',')
                for (raw in names) {
                    val name = raw.trim().lowercase().removePrefix("*.").trimEnd('.')
                    if (name.isEmpty()) continue
                    if (name == base || name.endsWith(".$base")) found.add(name)
                }
            }
        } catch (_: Exception) {
            return emptyList()
        }
        // Sort by depth then alphabetically so the registrable domain and apex come first.
        return found.sortedWith(compareBy({ it.count { c -> c == '.' } }, { it }))
    }
}
