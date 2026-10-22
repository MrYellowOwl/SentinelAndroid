package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayOutputStream

class SshAuditTest {
    private fun nameList(s: String): ByteArray {
        val bytes = s.toByteArray(Charsets.US_ASCII)
        val out = ByteArrayOutputStream()
        out.write(byteArrayOf((bytes.size shr 24).toByte(), (bytes.size shr 16).toByte(), (bytes.size shr 8).toByte(), bytes.size.toByte()))
        out.write(bytes)
        return out.toByteArray()
    }

    private fun kexPayload(kex: String, hostKey: String, enc: String, mac: String): ByteArray {
        val out = ByteArrayOutputStream()
        out.write(20)                       // SSH_MSG_KEXINIT
        out.write(ByteArray(16))            // cookie
        out.write(nameList(kex))            // kex_algorithms
        out.write(nameList(hostKey))        // server_host_key_algorithms
        out.write(nameList(enc))            // enc c2s
        out.write(nameList(enc))            // enc s2c
        out.write(nameList(mac))            // mac c2s
        out.write(nameList(mac))            // mac s2c
        out.write(nameList("none"))         // comp c2s
        out.write(nameList("none"))         // comp s2c
        return out.toByteArray()
    }

    @Test fun parsesNameLists() {
        val p = kexPayload("curve25519-sha256,diffie-hellman-group1-sha1", "ssh-ed25519,ssh-rsa", "aes256-gcm@openssh.com,3des-cbc", "hmac-sha2-256,hmac-md5")
        val k = SshAudit.parseKexInit(p)!!
        assertEquals(listOf("curve25519-sha256", "diffie-hellman-group1-sha1"), k.kex)
        assertEquals(listOf("ssh-ed25519", "ssh-rsa"), k.hostKey)
        assertTrue(k.encryption.contains("3des-cbc"))
    }

    @Test fun rejectsNonKexInit() {
        assertNull(SshAudit.parseKexInit(byteArrayOf(21, 0, 0)))
        assertNull(SshAudit.parseKexInit(ByteArray(0)))
    }

    @Test fun weakAlgorithmClassifiers() {
        assertTrue(SshAudit.weakKex("diffie-hellman-group1-sha1"))
        assertTrue(SshAudit.weakHostKey("ssh-dss"))
        assertTrue(SshAudit.weakHostKey("ssh-rsa"))
        assertTrue(SshAudit.weakCipher("3des-cbc"))
        assertTrue(SshAudit.weakCipher("aes128-cbc"))
        assertTrue(SshAudit.weakMac("hmac-md5"))
        assertTrue(SshAudit.weakMac("hmac-sha1"))
        assertTrue(!SshAudit.weakKex("curve25519-sha256"))
        assertTrue(!SshAudit.weakCipher("aes256-gcm@openssh.com"))
        assertTrue(!SshAudit.weakMac("hmac-sha2-256-etm@openssh.com"))
    }

    @Test fun findingsFlagEachWeakCategory() {
        val k = SshAudit.parseKexInit(kexPayload("diffie-hellman-group1-sha1", "ssh-rsa", "aes128-cbc", "hmac-md5"))!!
        val fs = SshAudit.findings("s", "1.2.3.4:22", "SSH-2.0-OpenSSH_7.4", k)
        assertTrue(fs.any { it.title.contains("key-exchange") })
        assertTrue(fs.any { it.title.contains("host-key") })
        assertTrue(fs.any { it.title.contains("cipher") })
        assertTrue(fs.any { it.title.contains("MAC") })
    }

    @Test fun modernServerJustGetsInfo() {
        val k = SshAudit.parseKexInit(kexPayload("curve25519-sha256", "ssh-ed25519", "aes256-gcm@openssh.com", "hmac-sha2-256-etm@openssh.com"))!!
        val fs = SshAudit.findings("s", "h:22", "SSH-2.0-OpenSSH_9.6", k)
        assertTrue(fs.none { it.severity == Severity.MEDIUM })
        assertEquals(1, fs.size)
    }
}
