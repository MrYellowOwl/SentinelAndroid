package com.yellowowl.sentinel

/**
 * Engagement scope: the CIDRs and domains the operator is authorized to assess. Pure matching so
 * the UI can label a target in- or out-of-scope and warn before acting outside it. Unit tested.
 * An empty scope means "not defined" — nothing is marked out of scope in that case.
 */
object Scope {
    data class Entry(val raw: String) {
        val isCidr: Boolean get() = raw.contains('/') && Ipv4.parse(raw.substringBefore('/')) != null
        val isIp: Boolean get() = Ipv4.parse(raw) != null
    }

    fun parse(text: String): List<Entry> =
        text.split('\n', ',', ' ', ';').map { it.trim() }.filter { it.isNotEmpty() }.map { Entry(it.lowercase()) }

    /** True when [target] (an IP, host:port, or domain) falls within any scope entry. */
    fun inScope(entries: List<Entry>, target: String): Boolean {
        if (entries.isEmpty()) return true
        val host = target.trim().lowercase().removePrefix("http://").removePrefix("https://").substringBefore('/').substringBefore(':')
        val ip = Ipv4.parse(host)
        for (e in entries) {
            when {
                e.isCidr && ip != null -> if (cidrContains(e.raw, ip)) return true
                e.isIp -> if (host == e.raw) return true
                else -> { // domain entry: exact or subdomain match
                    val d = e.raw.removePrefix("*.").trimEnd('.')
                    if (host == d || host.endsWith(".$d")) return true
                }
            }
        }
        return false
    }

    private fun cidrContains(cidr: String, ip: Long): Boolean {
        val base = Ipv4.parse(cidr.substringBefore('/')) ?: return false
        val prefix = cidr.substringAfter('/').toIntOrNull()?.takeIf { it in 0..32 } ?: return false
        if (prefix == 0) return true
        val mask = (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        return (base and mask) == (ip and mask)
    }

    /** Partition findings/targets for a report: those in scope and those outside it. */
    fun outOfScope(entries: List<Entry>, targets: List<String>): List<String> =
        if (entries.isEmpty()) emptyList() else targets.filterNot { inScope(entries, it) }.distinct()
}
