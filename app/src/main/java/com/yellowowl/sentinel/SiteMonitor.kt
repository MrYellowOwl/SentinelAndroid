package com.yellowowl.sentinel

/**
 * Expiry watch and run-to-run change detection for saved client projects. Pure and deterministic
 * (time is passed in), so it is cheap to unit-test and is reused by the report and the saved-client UI.
 *
 * "Expiry" surfaces how many days remain on the TLS certificate and the domain registration, always
 * (not only when nearly expired). "Changes" diffs the monitor snapshot of two runs — IP, name servers,
 * certificate, domain expiry, DNS records — so a developer sees what moved since the last audit.
 */
object SiteMonitor {

    enum class ExpiryLevel { OK, SOON, CRITICAL, EXPIRED, UNKNOWN }

    data class Expiry(val label: String, val date: String?, val daysRemaining: Int?, val level: ExpiryLevel)

    private const val DAY = 86_400_000L

    /** Parses a leading yyyy-MM-dd out of a WHOIS/date string into epoch millis (UTC midnight). */
    fun parseDate(s: String?): Long? {
        if (s.isNullOrBlank()) return null
        val m = Regex("""(\d{4})-(\d{2})-(\d{2})""").find(s) ?: return null
        return runCatching {
            val cal = java.util.GregorianCalendar(java.util.TimeZone.getTimeZone("UTC"))
            cal.clear()
            cal.set(m.groupValues[1].toInt(), m.groupValues[2].toInt() - 1, m.groupValues[3].toInt())
            cal.timeInMillis
        }.getOrNull()
    }

    private fun level(days: Int?): ExpiryLevel = when {
        days == null -> ExpiryLevel.UNKNOWN
        days < 0 -> ExpiryLevel.EXPIRED
        days <= 14 -> ExpiryLevel.CRITICAL
        days <= 45 -> ExpiryLevel.SOON
        else -> ExpiryLevel.OK
    }

    private fun daysFrom(targetMs: Long?, now: Long): Int? = targetMs?.let { ((it - now) / DAY).toInt() }

    /** Cert + domain expiry, as a short watch list. Omits an item only when neither a date nor days is known. */
    fun expiryWatch(p: SiteProfile, now: Long): List<Expiry> {
        val out = ArrayList<Expiry>()
        val certDays = daysFrom(p.certValidTo, now)
        if (p.certValidTo != null) {
            val d = isoDate(p.certValidTo)
            out.add(Expiry("TLS certificate", d, certDays, level(certDays)))
        }
        val domMs = parseDate(p.domainExpiry)
        if (domMs != null) {
            val dd = daysFrom(domMs, now)
            out.add(Expiry("Domain registration", isoDate(domMs), dd, level(dd)))
        }
        return out
    }

    private fun isoDate(ms: Long): String {
        val cal = java.util.GregorianCalendar(java.util.TimeZone.getTimeZone("UTC"))
        cal.timeInMillis = ms
        return "%04d-%02d-%02d".format(cal.get(java.util.Calendar.YEAR), cal.get(java.util.Calendar.MONTH) + 1, cal.get(java.util.Calendar.DAY_OF_MONTH))
    }

    /** Human-readable changes between an earlier run and a later one. Empty when nothing material moved. */
    fun changesSince(old: IntakeRun, new: IntakeRun): List<String> {
        val out = ArrayList<String>()
        if (!old.ip.isNullOrBlank() && !new.ip.isNullOrBlank() && old.ip != new.ip)
            out.add("Server IP changed: ${old.ip} → ${new.ip}")
        if (old.nameServers.isNotEmpty() && new.nameServers.isNotEmpty() &&
            old.nameServers.map { it.lowercase() }.toSet() != new.nameServers.map { it.lowercase() }.toSet())
            out.add("Name servers changed: ${old.nameServers.joinToString(", ")} → ${new.nameServers.joinToString(", ")}")
        if (!old.certIssuer.isNullOrBlank() && !new.certIssuer.isNullOrBlank() && old.certIssuer != new.certIssuer)
            out.add("Certificate issuer changed: ${old.certIssuer} → ${new.certIssuer}")
        if (old.certValidTo != null && new.certValidTo != null && old.certValidTo != new.certValidTo)
            out.add("Certificate renewed — expiry ${isoDate(old.certValidTo)} → ${isoDate(new.certValidTo)}")
        val oldDom = parseDate(old.domainExpiry); val newDom = parseDate(new.domainExpiry)
        if (oldDom != null && newDom != null && oldDom != newDom)
            out.add("Domain expiry changed: ${isoDate(oldDom)} → ${isoDate(newDom)}")
        if (!old.dnsSig.isNullOrBlank() && !new.dnsSig.isNullOrBlank() && old.dnsSig != new.dnsSig)
            out.add("DNS records changed since the last audit.")
        return out
    }
}
