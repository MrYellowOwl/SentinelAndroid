package com.yellowowl.sentinel

import org.json.JSONObject

/**
 * Pure parsing + finding-building for optional third-party intelligence lookups (Shodan, VirusTotal).
 * These are bring-your-own-key and read-only — passive context about an asset, no scanning by us.
 * The HTTP calls live in [NetToolsNet].
 */
object ExternalIntel {
    // ---- Shodan host ----
    data class ShodanInfo(
        val ip: String,
        val ports: List<Int>,
        val hostnames: List<String>,
        val org: String?,
        val os: String?,
        val vulns: List<String>
    )

    fun parseShodan(json: String): ShodanInfo? = try {
        val o = JSONObject(json)
        if (o.has("error")) null
        else {
            fun strList(key: String) = o.optJSONArray(key)?.let { a -> (0 until a.length()).mapNotNull { a.optString(it).ifBlank { null } } }.orEmpty()
            val ports = o.optJSONArray("ports")?.let { a -> (0 until a.length()).map { a.optInt(it) }.filter { it > 0 } }.orEmpty()
            ShodanInfo(
                ip = o.optString("ip_str").ifBlank { o.optString("ip_str") },
                ports = ports.sorted(),
                hostnames = strList("hostnames"),
                org = o.optString("org").ifBlank { null },
                os = o.optString("os").ifBlank { null },
                vulns = strList("vulns")
            )
        }
    } catch (_: Exception) { null }

    fun shodanFindings(scope: String, target: String, info: ShodanInfo): List<Finding> {
        val out = ArrayList<Finding>()
        out.add(Finding(
            title = "Shodan: external exposure of ${info.ip}", severity = Severity.INFO,
            source = FindingSource.NETWORK, scope = scope, target = target,
            details = listOfNotNull(
                info.ports.takeIf { it.isNotEmpty() }?.let { "Internet-facing ports: ${it.joinToString(", ")}" },
                info.org?.let { "Org: $it" }, info.os?.let { "OS: $it" },
                info.hostnames.takeIf { it.isNotEmpty() }?.let { "Hostnames: ${it.joinToString(", ")}" }
            ).joinToString(" · ").ifBlank { "No notable external data." },
            remediation = "Confirm every internet-facing port is intended; close or firewall anything unexpected."
        ))
        if (info.vulns.isNotEmpty()) out.add(Finding(
            title = "Shodan lists known CVEs for ${info.ip}", severity = Severity.MEDIUM,
            source = FindingSource.NETWORK, scope = scope, target = target,
            details = "Shodan associates these CVEs with this host: ${info.vulns.take(12).joinToString(", ")}${if (info.vulns.size > 12) "…" else ""}.",
            remediation = "Verify and patch these on the exposed services."
        ))
        return out
    }

    // ---- VirusTotal (IP or domain) ----
    data class VtInfo(val malicious: Int, val suspicious: Int, val harmless: Int, val reputation: Int)

    fun parseVirusTotal(json: String): VtInfo? = try {
        val stats = JSONObject(json).optJSONObject("data")?.optJSONObject("attributes")?.optJSONObject("last_analysis_stats")
        if (stats == null) null
        else VtInfo(
            malicious = stats.optInt("malicious"),
            suspicious = stats.optInt("suspicious"),
            harmless = stats.optInt("harmless"),
            reputation = JSONObject(json).optJSONObject("data")?.optJSONObject("attributes")?.optInt("reputation") ?: 0
        )
    } catch (_: Exception) { null }

    fun vtFinding(scope: String, target: String, info: VtInfo): Finding {
        val flagged = info.malicious + info.suspicious
        val sev = when {
            info.malicious >= 3 -> Severity.HIGH
            flagged > 0 -> Severity.MEDIUM
            else -> Severity.INFO
        }
        return Finding(
            title = if (flagged > 0) "VirusTotal: flagged by $flagged vendor(s)" else "VirusTotal: clean",
            severity = sev, source = FindingSource.WEB, scope = scope, target = target,
            details = "VirusTotal: ${info.malicious} malicious, ${info.suspicious} suspicious, ${info.harmless} harmless; community reputation ${info.reputation}.",
            remediation = if (flagged > 0) "Investigate why this asset is flagged (malware, phishing, prior compromise) before trusting it." else "No action needed."
        )
    }
}
