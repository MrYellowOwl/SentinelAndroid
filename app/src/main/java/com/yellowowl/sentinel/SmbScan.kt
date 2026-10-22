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

    // ---- SMBv1 (legacy; EternalBlue/WannaCry era) ----

    /** SMB1 SMB_COM_NEGOTIATE offering the "NT LM 0.12" dialect, wrapped in a NetBIOS session header. */
    fun smb1NegotiateRequest(): ByteArray {
        val header = ByteArray(32)
        byteArrayOf(0xFF.toByte(), 'S'.code.toByte(), 'M'.code.toByte(), 'B'.code.toByte()).copyInto(header, 0)
        header[4] = 0x72                      // SMB_COM_NEGOTIATE
        header[9] = 0x18                       // Flags (case-insensitive, canonical paths)
        // Flags2, PIDHigh, signature, TID/PID/UID/MID all left zero.
        val dialect = byteArrayOf(0x02) + "NT LM 0.12".toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        val body = byteArrayOf(0) +            // WordCount = 0
            byteArrayOf((dialect.size and 0xFF).toByte(), ((dialect.size shr 8) and 0xFF).toByte()) + // ByteCount (LE)
            dialect
        val smb = header + body
        val nb = byteArrayOf(0, ((smb.size shr 16) and 0xFF).toByte(), ((smb.size shr 8) and 0xFF).toByte(), (smb.size and 0xFF).toByte())
        return nb + smb
    }

    /** True if [raw] is a successful SMB1 NEGOTIATE response that selected a dialect (i.e. SMBv1 is enabled). */
    fun isSmb1Response(raw: ByteArray): Boolean {
        val smb = if (raw.size > 4 && raw[0].toInt() == 0 && (raw[4].toInt() and 0xFF) == 0xFF) raw.copyOfRange(4, raw.size) else raw
        if (smb.size < 35) return false
        if ((smb[0].toInt() and 0xFF) != 0xFF || smb[1].toInt() != 'S'.code || smb[2].toInt() != 'M'.code || smb[3].toInt() != 'B'.code) return false
        if ((smb[4].toInt() and 0xFF) != 0x72) return false                      // NEGOTIATE response
        val status = (smb[5].toInt() and 0xFF) or (smb[6].toInt() and 0xFF shl 8) or (smb[7].toInt() and 0xFF shl 16) or (smb[8].toInt() and 0xFF shl 24)
        if (status != 0) return false                                            // server errored
        val wordCount = smb[32].toInt() and 0xFF
        if (wordCount == 0) return false
        val dialectIndex = (smb[33].toInt() and 0xFF) or ((smb[34].toInt() and 0xFF) shl 8)
        return dialectIndex != 0xFFFF                                            // 0xFFFF = no dialect accepted
    }

    fun smbv1Finding(scope: String, target: String): Finding = Finding(
        title = "SMBv1 enabled", severity = Severity.HIGH, source = FindingSource.NETWORK, scope = scope, target = target,
        details = "The host responded to an SMBv1 negotiation. SMBv1 is obsolete and insecure (the EternalBlue/WannaCry family of exploits), and has no message signing by default.",
        remediation = "Disable SMBv1 entirely (Windows: remove the SMB1 feature; Samba: min protocol = SMB2). Nothing should still require it."
    )

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
