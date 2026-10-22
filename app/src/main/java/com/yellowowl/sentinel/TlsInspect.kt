package com.yellowowl.sentinel

/**
 * Pure logic for TLS/SSL assessment: classify protocols and ciphers, grade a host, and turn a
 * [TlsReport] into findings. The actual handshakes live in [TlsProbe].
 */
object TlsInspect {
    data class TlsReport(
        val host: String,
        val reachable: Boolean,
        val protocols: List<String> = emptyList(),              // supported, newest first
        val cipherByProtocol: Map<String, String> = emptyMap()  // protocol -> negotiated cipher
    ) {
        val ciphers: List<String> get() = cipherByProtocol.values.distinct()
    }

    // Protocols considered obsolete/insecure.
    private val WEAK_PROTOCOLS = setOf("SSLv2", "SSLv2Hello", "SSLv3", "TLSv1", "TLSv1.1")

    fun isWeakProtocol(p: String): Boolean = p in WEAK_PROTOCOLS

    /** Cipher-suite name fragments that indicate a broken or legacy cipher. */
    fun isWeakCipher(cipher: String): Boolean {
        val c = cipher.uppercase()
        return listOf("NULL", "EXPORT", "_ANON", "ANON_", "RC4", "_DES_", "DES_CBC", "3DES", "DES40", "_MD5").any { c.contains(it) }
    }

    /** A/B/C/F grade from the supported protocols and negotiated ciphers. */
    fun grade(report: TlsReport): String {
        if (!report.reachable || report.protocols.isEmpty()) return "?"
        val hasWeakProto = report.protocols.any { isWeakProtocol(it) }
        val hasWeakCipher = report.ciphers.any { isWeakCipher(it) }
        val worstBroken = report.protocols.any { it == "SSLv3" || it == "SSLv2" } ||
            report.ciphers.any { val c = it.uppercase(); c.contains("NULL") || c.contains("EXPORT") || c.contains("ANON") || c.contains("RC4") }
        return when {
            worstBroken -> "F"
            hasWeakProto || hasWeakCipher -> "C"
            report.protocols.contains("TLSv1.3") -> "A"
            else -> "B"  // TLS 1.2 only, modern ciphers
        }
    }

    fun findings(scope: String, host: String, report: TlsReport): List<Finding> {
        if (!report.reachable) return emptyList()
        val out = ArrayList<Finding>()

        val weakProtos = report.protocols.filter { isWeakProtocol(it) }
        if (weakProtos.isNotEmpty()) {
            out += Finding(
                title = "Obsolete TLS protocol enabled",
                severity = if (weakProtos.any { it == "SSLv3" || it == "SSLv2" }) Severity.HIGH else Severity.MEDIUM,
                source = FindingSource.WEB, scope = scope, target = host,
                details = "Server still accepts: ${weakProtos.joinToString(", ")}. These are deprecated and vulnerable to known downgrade/padding attacks.",
                remediation = "Disable SSLv3, TLS 1.0 and TLS 1.1 on the server; require TLS 1.2+ (ideally add TLS 1.3)."
            )
        }

        val weakCiphers = report.ciphers.filter { isWeakCipher(it) }
        if (weakCiphers.isNotEmpty()) {
            out += Finding(
                title = "Weak TLS cipher negotiated",
                severity = Severity.HIGH,
                source = FindingSource.WEB, scope = scope, target = host,
                details = "Negotiated a weak cipher: ${weakCiphers.joinToString(", ")}. RC4/3DES/DES/EXPORT/NULL/anon suites are broken or deprecated.",
                remediation = "Restrict the cipher list to modern AEAD suites (AES-GCM, ChaCha20-Poly1305) and drop legacy ciphers."
            )
        }

        if (!report.protocols.contains("TLSv1.3") && report.protocols.contains("TLSv1.2") && weakProtos.isEmpty()) {
            out += Finding(
                title = "TLS 1.3 not enabled",
                severity = Severity.LOW,
                source = FindingSource.WEB, scope = scope, target = host,
                details = "Server supports TLS 1.2 but not TLS 1.3. TLS 1.3 is faster and drops legacy cryptography.",
                remediation = "Enable TLS 1.3 on the server/load balancer if supported."
            )
        }

        val g = grade(report)
        out += Finding(
            title = "TLS configuration (grade $g)",
            severity = Severity.INFO,
            source = FindingSource.WEB, scope = scope, target = host,
            details = "Protocols: ${report.protocols.joinToString(", ")}." +
                (report.ciphers.takeIf { it.isNotEmpty() }?.let { " Ciphers: ${it.joinToString(", ")}." } ?: ""),
            remediation = if (g == "A") "Strong configuration — keep protocols and ciphers current."
            else "Aim for TLS 1.2+1.3 only with modern AEAD cipher suites."
        )
        return out
    }
}
