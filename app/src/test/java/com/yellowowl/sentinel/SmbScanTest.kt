package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SmbScanTest {
    /** Build a minimal SMB2 NEGOTIATE response with the given securityMode + dialect. */
    private fun response(securityMode: Int, dialect: Int, withNetbios: Boolean = true): ByteArray {
        val smb = ByteArray(72)
        smb[0] = 0xFE.toByte(); smb[1] = 'S'.code.toByte(); smb[2] = 'M'.code.toByte(); smb[3] = 'B'.code.toByte()
        fun le16(off: Int, v: Int) { smb[off] = (v and 0xFF).toByte(); smb[off + 1] = ((v shr 8) and 0xFF).toByte() }
        le16(64, 65)             // StructureSize
        le16(66, securityMode)   // SecurityMode
        le16(68, dialect)        // DialectRevision
        return if (withNetbios) byteArrayOf(0, 0, 0, smb.size.toByte()) + smb else smb
    }

    @Test fun requestIsWrappedWithNetbiosHeader() {
        val req = SmbScan.negotiateRequest()
        assertEquals(0, req[0].toInt())                    // NetBIOS type
        assertEquals(0xFE, req[4].toInt() and 0xFF)        // SMB2 magic after 4-byte header
    }

    @Test fun parsesSigningRequired() {
        val info = SmbScan.parseNegotiateResponse(response(securityMode = 0x03, dialect = 0x0311))!!
        assertTrue(info.signingRequired)
        assertTrue(info.signingEnabled)
        assertEquals(0x0311, info.dialect)
    }

    @Test fun parsesSigningNotRequired() {
        val info = SmbScan.parseNegotiateResponse(response(securityMode = 0x01, dialect = 0x0300))!!
        assertFalse(info.signingRequired)
        assertTrue(info.signingEnabled)
    }

    @Test fun parsesWithoutNetbiosHeader() {
        val info = SmbScan.parseNegotiateResponse(response(0x02, 0x0302, withNetbios = false))!!
        assertTrue(info.signingRequired)
        assertEquals("3.0.2", SmbScan.dialectName(info.dialect))
    }

    @Test fun rejectsNonSmb() {
        assertNull(SmbScan.parseNegotiateResponse(ByteArray(80)))
        assertNull(SmbScan.parseNegotiateResponse(byteArrayOf(1, 2, 3)))
    }

    /** Minimal SMB1 NEGOTIATE response: optional NetBIOS + SMB1 header + wordCount + dialectIndex. */
    private fun smb1Response(status: Int, wordCount: Int, dialectIndex: Int, withNetbios: Boolean = true): ByteArray {
        val smb = ByteArray(35)
        smb[0] = 0xFF.toByte(); smb[1] = 'S'.code.toByte(); smb[2] = 'M'.code.toByte(); smb[3] = 'B'.code.toByte()
        smb[4] = 0x72
        smb[5] = (status and 0xFF).toByte(); smb[6] = ((status shr 8) and 0xFF).toByte()
        smb[32] = (wordCount and 0xFF).toByte()
        smb[33] = (dialectIndex and 0xFF).toByte(); smb[34] = ((dialectIndex shr 8) and 0xFF).toByte()
        return if (withNetbios) byteArrayOf(0, 0, 0, smb.size.toByte()) + smb else smb
    }

    @Test fun smb1RequestOffersNtLm012() {
        val req = SmbScan.smb1NegotiateRequest()
        assertEquals(0, req[0].toInt())                 // NetBIOS type
        assertEquals(0xFF, req[4].toInt() and 0xFF)     // SMB1 magic after header
        assertEquals(0x72, req[8].toInt())              // SMB_COM_NEGOTIATE
        assertTrue(String(req, Charsets.US_ASCII).contains("NT LM 0.12"))
    }

    @Test fun detectsSmb1WhenDialectAccepted() {
        assertTrue(SmbScan.isSmb1Response(smb1Response(status = 0, wordCount = 17, dialectIndex = 0)))
        assertTrue(SmbScan.isSmb1Response(smb1Response(0, 17, 0, withNetbios = false)))
    }

    @Test fun rejectsSmb1WhenNoDialectOrError() {
        assertFalse(SmbScan.isSmb1Response(smb1Response(status = 0, wordCount = 17, dialectIndex = 0xFFFF))) // no dialect accepted
        assertFalse(SmbScan.isSmb1Response(smb1Response(status = 0x0034, wordCount = 17, dialectIndex = 0)))  // error status
        assertFalse(SmbScan.isSmb1Response(smb1Response(status = 0, wordCount = 0, dialectIndex = 0)))        // no words
        assertFalse(SmbScan.isSmb1Response(ByteArray(40)))                                                   // not an SMB header
    }

    @Test fun smbv1FindingIsHigh() {
        assertEquals(Severity.HIGH, SmbScan.smbv1Finding("s", "1.2.3.4:445").severity)
    }

    @Test fun findingsFlagNoSigning() {
        val fs = SmbScan.findings("s", "1.2.3.4:445", SmbScan.SmbInfo(0x0300, signingRequired = false, signingEnabled = true))
        assertTrue(fs.any { it.title == "SMB signing not required" && it.severity == Severity.MEDIUM })
        val ok = SmbScan.findings("s", "h", SmbScan.SmbInfo(0x0311, signingRequired = true, signingEnabled = true))
        assertTrue(ok.none { it.severity == Severity.MEDIUM })
    }
}
