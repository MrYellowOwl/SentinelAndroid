package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class TlsInspectTest {
    private fun report(protos: List<String>, ciphers: Map<String, String>) =
        TlsInspect.TlsReport("example.com", reachable = true, protocols = protos, cipherByProtocol = ciphers)

    @Test fun weakProtocolDetection() {
        assertTrue(TlsInspect.isWeakProtocol("TLSv1"))
        assertTrue(TlsInspect.isWeakProtocol("TLSv1.1"))
        assertTrue(TlsInspect.isWeakProtocol("SSLv3"))
        assertFalse(TlsInspect.isWeakProtocol("TLSv1.2"))
        assertFalse(TlsInspect.isWeakProtocol("TLSv1.3"))
    }

    @Test fun weakCipherDetection() {
        assertTrue(TlsInspect.isWeakCipher("TLS_RSA_WITH_RC4_128_SHA"))
        assertTrue(TlsInspect.isWeakCipher("SSL_RSA_WITH_3DES_EDE_CBC_SHA"))
        assertTrue(TlsInspect.isWeakCipher("TLS_RSA_WITH_NULL_SHA"))
        assertTrue(TlsInspect.isWeakCipher("TLS_DH_anon_WITH_AES_128_GCM_SHA256"))
        assertFalse(TlsInspect.isWeakCipher("TLS_AES_128_GCM_SHA256"))
        assertFalse(TlsInspect.isWeakCipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"))
    }

    @Test fun gradeA_forTls13ModernCiphers() {
        val r = report(listOf("TLSv1.3", "TLSv1.2"), mapOf("TLSv1.3" to "TLS_AES_256_GCM_SHA384", "TLSv1.2" to "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
        assertEquals("A", TlsInspect.grade(r))
        // Only an INFO finding (plus no TLS1.3-missing note).
        assertTrue(TlsInspect.findings("s", "h", r).all { it.severity == Severity.INFO })
    }

    @Test fun gradeB_forTls12OnlyModern() {
        val r = report(listOf("TLSv1.2"), mapOf("TLSv1.2" to "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
        assertEquals("B", TlsInspect.grade(r))
        assertTrue(TlsInspect.findings("s", "h", r).any { it.title.contains("TLS 1.3 not enabled") })
    }

    @Test fun gradeC_forLegacyProtocol() {
        val r = report(listOf("TLSv1.2", "TLSv1.1", "TLSv1"), mapOf("TLSv1.2" to "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"))
        assertEquals("C", TlsInspect.grade(r))
        assertTrue(TlsInspect.findings("s", "h", r).any { it.title.contains("Obsolete TLS protocol") && it.severity == Severity.MEDIUM })
    }

    @Test fun gradeF_forBrokenCipherOrSsl3() {
        val broken = report(listOf("TLSv1.2"), mapOf("TLSv1.2" to "TLS_RSA_WITH_RC4_128_MD5"))
        assertEquals("F", TlsInspect.grade(broken))
        assertTrue(TlsInspect.findings("s", "h", broken).any { it.title.contains("Weak TLS cipher") && it.severity == Severity.HIGH })
        val ssl3 = report(listOf("TLSv1.2", "SSLv3"), mapOf("TLSv1.2" to "TLS_AES_128_GCM_SHA256"))
        assertEquals("F", TlsInspect.grade(ssl3))
    }

    @Test fun unreachableGivesNoFindings() {
        val r = TlsInspect.TlsReport("h", reachable = false)
        assertEquals("?", TlsInspect.grade(r))
        assertTrue(TlsInspect.findings("s", "h", r).isEmpty())
    }
}
