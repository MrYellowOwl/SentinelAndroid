package com.yellowowl.sentinel

/** Pulls the fields a web dev needs out of raw WHOIS text: registrar, key dates, and name servers. Pure. */
object WhoisParse {
    data class WhoisInfo(
        val registrar: String?,
        val created: String?,
        val updated: String?,
        val expiry: String?,
        val nameServers: List<String>,
    )

    fun parse(raw: String): WhoisInfo {
        val lines = raw.lines().map { it.trim() }
        fun firstValue(labels: List<String>): String? {
            for (line in lines) {
                val i = line.indexOf(':')
                if (i <= 0) continue
                val key = line.substring(0, i).trim().lowercase()
                if (labels.any { key == it }) {
                    val v = line.substring(i + 1).trim()
                    if (v.isNotBlank() && !v.startsWith("http")) return v
                }
            }
            return null
        }
        val ns = lines.mapNotNull { line ->
            val i = line.indexOf(':')
            if (i <= 0) return@mapNotNull null
            val key = line.substring(0, i).trim().lowercase()
            if (key == "name server" || key == "nserver" || key == "name servers") {
                line.substring(i + 1).trim().substringBefore(' ').trimEnd('.').lowercase().ifBlank { null }
            } else null
        }.distinct()

        return WhoisInfo(
            registrar = firstValue(listOf("registrar", "sponsoring registrar")),
            created = firstValue(listOf("creation date", "created on", "created", "registered on", "registration time", "domain registration date")),
            updated = firstValue(listOf("updated date", "last updated", "last modified", "last-update")),
            expiry = firstValue(listOf("registry expiry date", "registrar registration expiration date", "expiration date", "expiry date", "paid-till", "expire date")),
            nameServers = ns,
        )
    }
}
