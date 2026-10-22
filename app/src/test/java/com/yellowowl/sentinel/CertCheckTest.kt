package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CertCheckTest {
    private fun info(
        sigAlg: String? = "SHA256withRSA",
        keyAlgo: String? = "RSA",
        keyBits: Int = 2048,
        selfSigned: Boolean = false
    ) = CertCheck.CertInfo(notAfter = null, sigAlg = sigAlg, keyAlgo = keyAlgo, keyBits = keyBits, selfSigned = selfSigned)

    private fun titles(info: CertCheck.CertInfo) = CertCheck.findings("s", "h", info).map { it.title }

    @Test fun strongModernCertHasNoFindings() {
        assertTrue(CertCheck.findings("s", "h", info()).isEmpty())
        assertTrue(CertCheck.findings("s", "h", info(keyAlgo = "EC", keyBits = 256)).isEmpty())
    }

    @Test fun md5SignatureIsHigh() {
        val f = CertCheck.findings("s", "h", info(sigAlg = "MD5withRSA")).single { it.title.contains("broken") }
        assertEquals(Severity.HIGH, f.severity)
    }

    @Test fun sha1SignatureIsMedium() {
        val f = CertCheck.findings("s", "h", info(sigAlg = "SHA1withRSA")).single { it.title.contains("SHA-1") }
        assertEquals(Severity.MEDIUM, f.severity)
    }

    @Test fun rsaKeyTooSmall() {
        assertEquals(Severity.MEDIUM, CertCheck.findings("s", "h", info(keyBits = 1024)).single { it.title.contains("RSA") }.severity)
        assertEquals(Severity.HIGH, CertCheck.findings("s", "h", info(keyBits = 512)).single { it.title.contains("RSA") }.severity)
    }

    @Test fun weakEcKey() {
        val f = CertCheck.findings("s", "h", info(keyAlgo = "EC", keyBits = 192)).single { it.title.contains("EC") }
        assertEquals(Severity.MEDIUM, f.severity)
    }

    @Test fun selfSignedIsMedium() {
        val f = CertCheck.findings("s", "h", info(selfSigned = true)).single { it.title.contains("Self-signed") }
        assertEquals(Severity.MEDIUM, f.severity)
    }

    @Test fun zeroKeyBitsIsNotFlagged() {
        // Unknown key size (bits == 0) should not produce a weak-key false positive.
        assertTrue(titles(info(keyBits = 0)).none { it.contains("Weak certificate key") })
    }
}
