package com.yellowowl.sentinel

/**
 * Sends a single SMB2 NEGOTIATE and reads the server's reply to assess two things without any
 * authentication or share access: the highest SMB dialect, and whether message signing is required
 * (signing-not-required enables NTLM relay). Pure build/parse here; the socket is in [NetToolsNet].
 */
object SmbScan {
    private val DIALECTS = intArrayOf(0x0202, 0x0210, 0x0300, 0x0302) // 2.0.2 … 3.0.2 (no 3.1.1 negotiate contexts)

    fun dialectName(rev: Int): String = when (rev) {
        0x0202 -> "2.0.2"; 0x0210 -> "2.1"; 0x0300 -> "3.0"; 0x0302 -> "3.0.2"; 0x0311 -> "3.1.1"
        else -> "0x%04x".format(rev)
    }

    /** SMB2 NEGOTIATE request wrapped in its 4-byte NetBIOS session header, ready to send on TCP 445. */
    fun negotiateRequest(): ByteArray {
        fun le16(v: Int) = byteArrayOf((v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte())
        val header = ByteArray(64)
        byteArrayOf(0xFE.toByte(), 'S'.code.toByte(), 'M'.code.toByte(), 'B'.code.toByte()).copyInto(header, 0)
        le16(64).copyInto(header, 4)   // StructureSize
        le16(1).copyInto(header, 14)   // CreditRequest (Command=0 NEGOTIATE already zero at offset 12)

        val body = ArrayList<Byte>()
        fun addLe16(v: Int) { body.add((v and 0xFF).toByte()); body.add(((v shr 8) and 0xFF).toByte()) }
        addLe16(36)                    // StructureSize
        addLe16(DIALECTS.size)         // DialectCount
        addLe16(0x0001)                // SecurityMode = SIGNING_ENABLED
        addLe16(0)                     // Reserved
        repeat(4) { body.add(0) }      // Capabilities
        repeat(16) { body.add(0) }     // ClientGuid
        repeat(8) { body.add(0) }      // ClientStartTime (no 3.1.1 → not negotiate-context offsets)
        DIALECTS.forEach { addLe16(it) }

        val smb = header + body.toByteArray()
        // NetBIOS session header: 1 byte type (0) + 3-byte big-endian length.
        val nb = byteArrayOf(0, ((smb.size shr 16) and 0xFF).toByte(), ((smb.size shr 8) and 0xFF).toByte(), (smb.size and 0xFF).toByte())
        return nb + smb
    }

    data class SmbInfo(val dialect: Int, val signingRequired: Boolean, val signingEnabled: Boolean)

    /** Parse an SMB2 NEGOTIATE response. Input may still carry the 4-byte NetBIOS header. */
    fun parseNegotiateResponse(raw: ByteArray): SmbInfo? {
        // Skip a NetBIOS header if present (type byte 0x00 then 3-byte length).
        val smb = if (raw.size > 4 && raw[0].toInt() == 0 && raw[4].toInt() and 0xFF == 0xFE) raw.copyOfRange(4, raw.size) else raw
        if (smb.size < 72) return null
        if (smb[0].toInt() and 0xFF != 0xFE || smb[1].toInt() != 'S'.code || smb[2].toInt() != 'M'.code || smb[3].toInt() != 'B'.code) return null
        // NEGOTIATE response body begins right after the 64-byte header.
        val b = 64
        fun le16(off: Int) = (smb[off].toInt() and 0xFF) or ((smb[off + 1].toInt() and 0xFF) shl 8)
        val structSize = le16(b)
        if (structSize != 65) return null
        val securityMode = le16(b + 2)
        val dialect = le16(b + 4)
        return SmbInfo(dialect, signingRequired = securityMode and 0x02 != 0, signingEnabled = securityMode and 0x01 != 0)
    }

    fun findings(scope: String, target: String, info: SmbInfo): List<Finding> {
        val out = ArrayList<Finding>()
        fun f(title: String, sev: Severity, details: String, fix: String) =
            out.add(Finding(title = title, severity = sev, source = FindingSource.NETWORK, scope = scope, target = target, details = details, remediation = fix))

        if (!info.signingRequired) f("SMB signing not required", Severity.MEDIUM,
            "The SMB server (dialect ${dialectName(info.dialect)}) does not require message signing, which enables NTLM relay attacks on the network.",
            "Require SMB signing (GPO 'Microsoft network server: Digitally sign communications (always)' / 'server signing = mandatory').")

        if (info.dialect == 0x0202) f("Legacy SMB dialect negotiated (2.0.2)", Severity.LOW,
            "The highest dialect negotiated was SMB 2.0.2 — a very old revision.",
            "Enable newer SMB dialects (3.x) and disable SMB 1.0 entirely.")

        f("SMB service (assessment)", Severity.INFO,
            "SMB dialect ${dialectName(info.dialect)}; signing ${if (info.signingRequired) "required" else if (info.signingEnabled) "enabled but not required" else "disabled"}.",
            if (info.signingRequired) "No action needed." else "Require SMB signing and disable SMBv1.")
        return out
    }
}
