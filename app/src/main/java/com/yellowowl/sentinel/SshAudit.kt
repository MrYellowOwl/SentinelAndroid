package com.yellowowl.sentinel

/**
 * Parses an SSH server's identification banner and its SSH_MSG_KEXINIT algorithm offer, and flags
 * weak/legacy algorithms. Read-only: it reads what the server advertises during the handshake and
 * never authenticates. Pure + unit tested; the socket read lives in [NetToolsNet].
 */
object SshAudit {
    data class SshKex(
        val kex: List<String>,
        val hostKey: List<String>,
        val encryption: List<String>,
        val mac: List<String>
    )

    /** Parse the KEXINIT payload (first byte = 20, then 16-byte cookie, then ten name-lists). */
    fun parseKexInit(payload: ByteArray): SshKex? {
        if (payload.isEmpty() || (payload[0].toInt() and 0xFF) != 20) return null
        var p = 1 + 16 // msg type + cookie
        fun nameList(): List<String>? {
            if (p + 4 > payload.size) return null
            val len = ((payload[p].toInt() and 0xFF) shl 24) or ((payload[p + 1].toInt() and 0xFF) shl 16) or
                ((payload[p + 2].toInt() and 0xFF) shl 8) or (payload[p + 3].toInt() and 0xFF)
            p += 4
            if (len < 0 || p + len > payload.size) return null
            val s = String(payload, p, len, Charsets.US_ASCII)
            p += len
            return if (s.isEmpty()) emptyList() else s.split(',')
        }
        val kex = nameList() ?: return null
        val hostKey = nameList() ?: return null
        val encC2s = nameList() ?: return null
        val encS2c = nameList() ?: return null
        val macC2s = nameList() ?: return null
        val macS2c = nameList() ?: return null
        return SshKex(kex, hostKey, (encC2s + encS2c).distinct(), (macC2s + macS2c).distinct())
    }

    fun weakKex(a: String): Boolean {
        val k = a.lowercase().substringBefore('@')  // ignore vendor suffixes like @openssh.com
        // Any SHA-1 key exchange is deprecated (covers group1/group14/group-exchange-sha1, rsa1024-sha1);
        // group1 is 1024-bit MODP; GSSAPI KEX is frequently misconfigured.
        return k.endsWith("sha1") || k.contains("group1-") || k.startsWith("gss-")
    }

    fun weakHostKey(a: String): Boolean {
        val k = a.lowercase()
        return k == "ssh-dss" || k == "ssh-rsa" || k.startsWith("ssh-rsa-cert") || k == "x509v3-sign-rsa"
    }

    fun weakCipher(a: String): Boolean {
        val k = a.lowercase()
        return k.contains("3des") || k.contains("arcfour") || k.contains("-cbc") || k.startsWith("des") ||
            k.contains("blowfish") || k.contains("cast128") || k.contains("none")
    }

    fun weakMac(a: String): Boolean {
        val k = a.lowercase()
        return k.contains("md5") || k.contains("hmac-sha1") || k.endsWith("-96") || k == "none"
    }

    fun findings(scope: String, target: String, banner: String?, kex: SshKex?): List<Finding> {
        val out = ArrayList<Finding>()
        fun f(title: String, sev: Severity, details: String, fix: String) =
            out.add(Finding(title = title, severity = sev, source = FindingSource.NETWORK, scope = scope, target = target, details = details, remediation = fix))

        if (kex == null) {
            if (banner != null) f("SSH service detected", Severity.INFO, "SSH banner: ${banner.take(80)}.",
                "No action needed; couldn't read the algorithm offer to assess it.")
            return out
        }

        val badKex = kex.kex.filter { weakKex(it) }
        val badHk = kex.hostKey.filter { weakHostKey(it) }
        val badEnc = kex.encryption.filter { weakCipher(it) }
        val badMac = kex.mac.filter { weakMac(it) }

        if (badKex.isNotEmpty()) f("Weak SSH key-exchange offered", Severity.MEDIUM,
            "Server offers weak KEX: ${badKex.joinToString(", ")}. SHA-1 / Group1 exchanges are deprecated.",
            "Restrict KexAlgorithms to curve25519-sha256 and diffie-hellman-group16/18-sha512.")
        if (badHk.isNotEmpty()) f("Weak SSH host-key algorithm", Severity.MEDIUM,
            "Server offers SHA-1/DSA host keys: ${badHk.joinToString(", ")}.",
            "Prefer ssh-ed25519 and rsa-sha2-512/256; disable ssh-dss and ssh-rsa (SHA-1).")
        if (badEnc.isNotEmpty()) f("Weak SSH cipher offered", Severity.MEDIUM,
            "Server offers legacy ciphers: ${badEnc.joinToString(", ")}. CBC/3DES/arcfour are weak.",
            "Restrict Ciphers to AEAD/CTR suites (chacha20-poly1305, aes256-gcm, aes256-ctr).")
        if (badMac.isNotEmpty()) f("Weak SSH MAC offered", Severity.LOW,
            "Server offers weak MACs: ${badMac.joinToString(", ")}. MD5/SHA-1/-96 are deprecated.",
            "Restrict MACs to encrypt-then-MAC SHA-2 (hmac-sha2-512-etm, hmac-sha2-256-etm).")

        f("SSH algorithms (assessment)", Severity.INFO,
            "KEX: ${kex.kex.take(4).joinToString(", ")}… · HostKey: ${kex.hostKey.joinToString(", ")} · Ciphers: ${kex.encryption.take(4).joinToString(", ")}…" +
                (banner?.let { " · Banner: ${it.take(60)}" } ?: ""),
            if (badKex.isEmpty() && badHk.isEmpty() && badEnc.isEmpty() && badMac.isEmpty()) "Algorithm selection looks modern." else "Harden the SSH algorithm lists as noted above.")
        return out
    }
}
