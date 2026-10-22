package com.yellowowl.sentinel

/**
 * Maps a finding to the control frameworks a pentest report is usually expected to reference
 * (OWASP Top 10 2021 + a CIS Controls v8 safeguard). Pure keyword matching, unit tested.
 */
object Compliance {
    data class Tag(val owasp: String?, val cis: String?) {
        val labels: List<String> get() = listOfNotNull(owasp, cis)
    }

    /** Keyword → (OWASP, CIS). First match on the finding's title/details wins. */
    private val rules: List<Triple<Regex, String, String>> = listOf(
        Triple(Regex("CVE-|end-of-life|vulnerab|exploit", RegexOption.IGNORE_CASE), "A06: Vulnerable & Outdated Components", "CIS 7: Continuous Vulnerability Management"),
        Triple(Regex("TLS|SSL|cipher|HSTS|certificate|cleartext|HTTPS", RegexOption.IGNORE_CASE), "A02: Cryptographic Failures", "CIS 3: Data Protection"),
        Triple(Regex("SPF|DMARC|DKIM|DNSSEC|CAA|spoof", RegexOption.IGNORE_CASE), "A05: Security Misconfiguration", "CIS 9: Email & Web Browser Protections"),
        Triple(Regex("CORS|CSP|clickjack|X-Frame|nosniff|Referrer|header|SameSite|cookie", RegexOption.IGNORE_CASE), "A05: Security Misconfiguration", "CIS 4: Secure Configuration"),
        Triple(Regex("SMB|SNMP|Telnet|RDP|VNC|signing|default comm|open port|exposed service", RegexOption.IGNORE_CASE), "A05: Security Misconfiguration", "CIS 4: Secure Configuration"),
        Triple(Regex("\\.git|\\.env|backup|phpinfo|server-status|exposed|debug\\.log|listing|disclos", RegexOption.IGNORE_CASE), "A01: Broken Access Control", "CIS 3: Data Protection"),
        Triple(Regex("user enum|xmlrpc|author|REST API|login|credential", RegexOption.IGNORE_CASE), "A07: Identification & Authentication Failures", "CIS 6: Access Control Management"),
        Triple(Regex("SSH|key-exchange|host-key|MAC", RegexOption.IGNORE_CASE), "A02: Cryptographic Failures", "CIS 4: Secure Configuration")
    )

    fun tag(finding: Finding): Tag {
        val hay = "${finding.title}\n${finding.details}"
        val m = rules.firstOrNull { it.first.containsMatchIn(hay) }
        return if (m == null) Tag(null, null) else Tag(m.second, m.third)
    }
}
