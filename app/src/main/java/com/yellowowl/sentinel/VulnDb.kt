package com.yellowowl.sentinel

/**
 * Local known-vulnerability knowledge base and the logic that matches a fingerprinted service against it.
 * All comparison/matching is pure and unit tested; fetching/caching the feed lives in [VulnFeed].
 *
 * This matches versions to published CVEs so the operator knows what to fix. It never contains or runs
 * exploit code: `exploitAvailable` is only a priority flag sourced from a public index.
 */

/** A dotted software version with optional suffixes ("8.2p1", "2.4.41", "10.3.25-MariaDB"). */
class SoftwareVersion private constructor(private val parts: List<Part>) : Comparable<SoftwareVersion> {
    private sealed interface Part
    private data class Num(val value: Long) : Part
    private data class Text(val value: String) : Part

    override fun compareTo(other: SoftwareVersion): Int {
        val max = maxOf(parts.size, other.parts.size)
        for (i in 0 until max) {
            val a = parts.getOrElse(i) { Num(0) }
            val b = other.parts.getOrElse(i) { Num(0) }
            val c = compareParts(a, b)
            if (c != 0) return c
        }
        return 0
    }

    private fun compareParts(a: Part, b: Part): Int = when {
        a is Num && b is Num -> a.value.compareTo(b.value)
        a is Text && b is Text -> a.value.compareTo(b.value)
        a is Num -> 1   // a numeric part outranks a textual one (release > pre-release)
        else -> -1
    }

    override fun equals(other: Any?): Boolean = other is SoftwareVersion && compareTo(other) == 0
    override fun hashCode(): Int = parts.filterIsInstance<Num>().sumOf { it.value }.toInt()
    override fun toString(): String = parts.joinToString(".") { if (it is Num) it.value.toString() else (it as Text).value }

    companion object {
        /** Splits into maximal digit / non-digit runs, dropping separators. Returns null if no usable token. */
        fun parse(raw: String): SoftwareVersion? {
            val parts = ArrayList<Part>()
            val token = StringBuilder()
            var tokenIsDigit = false
            fun flush() {
                if (token.isEmpty()) return
                parts.add(if (tokenIsDigit) Num(token.toString().toLongOrNull() ?: 0) else Text(token.toString().lowercase()))
                token.clear()
            }
            for (ch in raw.trim()) {
                when {
                    ch.isDigit() -> { if (token.isNotEmpty() && !tokenIsDigit) flush(); tokenIsDigit = true; token.append(ch) }
                    ch.isLetter() -> { if (token.isNotEmpty() && tokenIsDigit) flush(); tokenIsDigit = false; token.append(ch) }
                    else -> flush() // separator
                }
            }
            flush()
            return if (parts.isEmpty()) null else SoftwareVersion(parts)
        }
    }
}

/** Affected-version range: [introduced, fixed) plus any explicitly listed versions. Empty = all versions. */
data class VersionRange(
    val introduced: String? = null, // inclusive lower bound
    val fixed: String? = null,      // exclusive upper bound ("fixed in")
    val exact: List<String> = emptyList()
) {
    fun contains(version: SoftwareVersion): Boolean {
        if (exact.isNotEmpty() && exact.mapNotNull(SoftwareVersion::parse).any { it == version }) return true
        if (exact.isNotEmpty() && introduced == null && fixed == null) return false
        val aboveLower = introduced?.let { SoftwareVersion.parse(it)?.let { lo -> version >= lo } ?: true } ?: true
        val belowUpper = fixed?.let { SoftwareVersion.parse(it)?.let { hi -> version < hi } ?: true } ?: true
        return aboveLower && belowUpper
    }
}

data class KnownVuln(
    val id: String,              // e.g. "CVE-2021-28041"
    val product: String,         // normalized product key, matches ServiceFingerprint.productKey
    val range: VersionRange,
    val cvss: Double? = null,    // CVSS base score 0–10
    val summary: String = "",
    val exploitAvailable: Boolean = false,
    val referenceUrl: String? = null,
    val fixText: String? = null  // overrides the auto "upgrade to X" message when a CVE needs specific guidance
) {
    val severity: Severity = severityOf(cvss, exploitAvailable)

    /** Turns a match on a host:port into a saved finding. */
    fun toFinding(scope: String, ip: String, port: Int, fingerprint: ServiceFingerprint): Finding {
        val exploitNote = if (exploitAvailable) " A public exploit is known to exist, so treat this as a priority." else ""
        val score = cvss?.let { " (CVSS $it)" }.orEmpty()
        val fix = fixText
            ?: range.fixed?.let { "Upgrade ${fingerprint.product} to $it or later." }
            ?: "Apply the vendor's patch or mitigation for $id."
        return Finding(
            title = "$id in ${fingerprint.display}",
            severity = severity,
            source = FindingSource.NETWORK,
            scope = scope,
            target = "$ip:$port",
            details = buildString {
                append(summary.ifBlank { "$id affects ${fingerprint.display}." })
                append(score)
                append(exploitNote)
            }.trim(),
            remediation = listOfNotNull(fix, referenceUrl?.let { "Details: $it" }).joinToString(" ")
        )
    }

    companion object {
        fun severityOf(cvss: Double?, exploitAvailable: Boolean): Severity {
            val base = when {
                cvss == null -> Severity.MEDIUM
                cvss >= 7.0 -> Severity.HIGH
                cvss >= 4.0 -> Severity.MEDIUM
                cvss > 0.0 -> Severity.LOW
                else -> Severity.INFO
            }
            // Something with a public exploit is at least high priority, even at a middling CVSS.
            return if (exploitAvailable && base.rank < Severity.HIGH.rank) Severity.HIGH else base
        }
    }
}

/** Matches fingerprinted services against the loaded vulnerability entries. */
class VulnMatcher(entries: List<KnownVuln>) {
    private val byProduct: Map<String, List<KnownVuln>> = entries.groupBy { normalize(it.product) }

    /** CVEs affecting this service, most severe first; exploit-available wins ties. */
    fun match(fingerprint: ServiceFingerprint): List<KnownVuln> {
        val version = fingerprint.version?.let(SoftwareVersion::parse) ?: return emptyList()
        val candidates = byProduct[normalize(fingerprint.productKey)].orEmpty()
        return candidates
            .filter { it.range.contains(version) }
            .sortedWith(
                compareByDescending<KnownVuln> { it.severity.rank }
                    .thenByDescending { it.exploitAvailable }
                    .thenByDescending { it.cvss ?: 0.0 }
            )
    }

    fun findingsFor(scope: String, device: DeviceResult): List<Finding> =
        device.openPorts.flatMap { port ->
            val fp = port.fingerprint ?: return@flatMap emptyList()
            match(fp).map { it.toFinding(scope, device.ipAddress, port.port, fp) }
        }

    companion object {
        /** Folds vendor naming differences so "apache"/"apache_httpd" and "iis"/"microsoft_iis" line up. */
        private val aliases = mapOf(
            "apache" to "apache_httpd",
            "httpd" to "apache_httpd",
            "iis" to "microsoft_iis",
            "openssh_server" to "openssh"
        )

        fun normalize(key: String): String {
            val k = key.lowercase().replace(' ', '_').replace('-', '_')
            return aliases[k] ?: k
        }
    }
}
