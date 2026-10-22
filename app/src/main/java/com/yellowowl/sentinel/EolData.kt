package com.yellowowl.sentinel

/**
 * Flags software whose release branch is past end-of-life, even when no specific CVE matches —
 * an unsupported branch gets no security fixes, which is itself a finding. Pure + unit tested.
 *
 * Kept conservative (branches that are unambiguously EOL as of the app's build) to avoid false
 * positives on rolling-release software; extend as needed.
 */
object EolData {
    /** product key -> set of EOL "major.minor" branches, with a short note. */
    private val eolBranches: Map<String, Map<String, String>> = mapOf(
        "php" to mapOf(
            "5" to "PHP 5.x", "7.0" to "PHP 7.0", "7.1" to "PHP 7.1", "7.2" to "PHP 7.2",
            "7.3" to "PHP 7.3", "7.4" to "PHP 7.4", "8.0" to "PHP 8.0", "8.1" to "PHP 8.1"
        ).withNote("Upgrade to a supported PHP branch (8.2+). EOL branches get no security fixes."),
        "apache_httpd" to mapOf(
            "1.3" to "Apache 1.3", "2.0" to "Apache httpd 2.0", "2.2" to "Apache httpd 2.2"
        ).withNote("Upgrade to Apache httpd 2.4.x; older branches are end-of-life."),
        "mysql" to mapOf(
            "5.0" to "MySQL 5.0", "5.1" to "MySQL 5.1", "5.5" to "MySQL 5.5",
            "5.6" to "MySQL 5.6", "5.7" to "MySQL 5.7"
        ).withNote("Upgrade to MySQL 8.0+; these branches are end-of-life."),
        "mariadb" to mapOf(
            "5.5" to "MariaDB 5.5", "10.0" to "MariaDB 10.0", "10.1" to "MariaDB 10.1",
            "10.2" to "MariaDB 10.2", "10.3" to "MariaDB 10.3", "10.4" to "MariaDB 10.4", "10.5" to "MariaDB 10.5"
        ).withNote("Upgrade to a maintained MariaDB release (11.x or a current 10.6+ LTS).")
    )

    private fun Map<String, String>.withNote(note: String): Map<String, String> =
        mapValues { (_, label) -> "$label is past end-of-life. $note" }

    /** The branch label for an EOL match, or null. */
    fun eolNote(product: String, version: String?): String? {
        val v = version ?: return null
        val branches = eolBranches[VulnMatcher.normalize(product)] ?: return null
        val major = v.trim().substringBefore('.').takeWhile { it.isDigit() }
        val majorMinor = run {
            val bits = v.trim().split('.')
            if (bits.size >= 2) "${bits[0]}.${bits[1].takeWhile { c -> c.isDigit() }}" else major
        }
        return branches[majorMinor] ?: branches[major]
    }

    /** An EOL finding for a fingerprinted service, or null when the branch is still supported. */
    fun finding(scope: String, target: String, fingerprint: ServiceFingerprint, source: String = FindingSource.NETWORK): Finding? {
        val note = eolNote(fingerprint.productKey, fingerprint.version) ?: return null
        return Finding(
            title = "End-of-life software: ${fingerprint.display}",
            severity = Severity.MEDIUM,
            source = source,
            scope = scope,
            target = target,
            details = note,
            remediation = "Plan an upgrade to a supported release; unsupported branches receive no security patches."
        )
    }
}
