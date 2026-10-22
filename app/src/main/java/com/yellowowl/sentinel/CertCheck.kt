package com.yellowowl.sentinel

/**
 * Assesses the strength of a server's TLS leaf certificate: signature algorithm, key size, and
 * whether it's self-signed. Pure classification (the certificate is read in [WebsiteAuditor]).
 */
object CertCheck {
    data class CertInfo(
        val notAfter: Long?,     // epoch millis of expiry (used by the existing expiry check)
        val sigAlg: String?,     // e.g. "SHA256withRSA", "SHA1withRSA"
        val keyAlgo: String?,    // "RSA", "EC", …
        val keyBits: Int,        // key size in bits (0 if unknown)
        val selfSigned: Boolean
    )

    fun findings(scope: String, host: String, info: CertInfo): List<Finding> {
        val out = ArrayList<Finding>()
        fun f(title: String, sev: Severity, details: String, fix: String) =
            out.add(Finding(title = title, severity = sev, source = FindingSource.WEB, scope = scope, target = host, details = details, remediation = fix))

        val sig = info.sigAlg?.uppercase().orEmpty()
        when {
            sig.contains("MD5") || sig.contains("MD2") -> f("Certificate uses a broken signature algorithm", Severity.HIGH,
                "The TLS certificate is signed with ${info.sigAlg} — MD5/MD2 are broken and allow forgery.",
                "Reissue the certificate with SHA-256 (free from Let's Encrypt).")
            sig.contains("SHA1") -> f("Certificate signed with SHA-1", Severity.MEDIUM,
                "The TLS certificate uses ${info.sigAlg}. SHA-1 is deprecated and distrusted by modern browsers.",
                "Reissue the certificate with a SHA-256 signature.")
        }

        if (info.keyAlgo == "RSA" && info.keyBits in 1 until 2048) {
            f("Weak certificate key (RSA ${info.keyBits}-bit)", if (info.keyBits < 1024) Severity.HIGH else Severity.MEDIUM,
                "The certificate's RSA key is ${info.keyBits}-bit; 2048-bit is the modern minimum.",
                "Reissue with a 2048-bit (or stronger) RSA key, or an ECDSA P-256 key.")
        } else if (info.keyAlgo == "EC" && info.keyBits in 1 until 256) {
            f("Weak certificate key (EC ${info.keyBits}-bit)", Severity.MEDIUM,
                "The certificate's elliptic-curve key is ${info.keyBits}-bit; P-256 (256-bit) is the practical minimum.",
                "Reissue with a P-256 or stronger curve.")
        }

        if (info.selfSigned) f("Self-signed certificate", Severity.MEDIUM,
            "The certificate is self-signed (issuer equals subject), so browsers won't trust it and users get security warnings — and it offers no protection against interception.",
            "Install a certificate from a trusted CA (free from Let's Encrypt).")

        return out
    }
}
