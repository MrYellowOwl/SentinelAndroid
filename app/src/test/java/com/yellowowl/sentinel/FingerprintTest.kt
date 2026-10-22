package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class FingerprintTest {
    private fun bytes(s: String) = s.toByteArray(Charsets.US_ASCII)

    @Test
    fun sshOpenSsh() {
        val fp = Fingerprint.parse(ProbeKind.READ_ON_CONNECT, 22, bytes("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1\r\n"))!!
        assertEquals("OpenSSH", fp.product)
        assertEquals("8.2p1", fp.version)
        assertEquals("Ubuntu-4ubuntu0.1", fp.extra)
        assertEquals("OpenSSH 8.2p1", fp.display)
    }

    @Test
    fun sshDropbearAndCisco() {
        val d = Fingerprint.parseBanner(22, "SSH-2.0-dropbear_2019.78")!!
        assertEquals("dropbear", d.product); assertEquals("2019.78", d.version)
        val c = Fingerprint.parseBanner(22, "SSH-1.99-Cisco-1.25")!!
        assertEquals("Cisco", c.product); assertEquals("1.25", c.version)
    }

    @Test
    fun ftpVariants() {
        assertEquals("3.0.3", Fingerprint.parseBanner(21, "220 (vsFTPd 3.0.3)")!!.version)
        val pro = Fingerprint.parseBanner(21, "220 ProFTPD 1.3.5 Server ready")!!
        assertEquals("1.3.5", pro.version)
        assertEquals("FTP", Fingerprint.parseBanner(21, "220 Welcome")!!.product)
    }

    @Test
    fun httpServerHeaders() {
        val apache = Fingerprint.parse(ProbeKind.HTTP_HEAD, 80, bytes("HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n"))!!
        assertEquals("Apache httpd", apache.product); assertEquals("2.4.41", apache.version); assertEquals("Ubuntu", apache.extra)
        val nginx = Fingerprint.parseHttpServer("HTTP/1.1 301\r\nServer: nginx/1.18.0\r\n")!!
        assertEquals("nginx", nginx.product); assertEquals("1.18.0", nginx.version)
        val iis = Fingerprint.parseHttpServer("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n")!!
        assertEquals("Microsoft IIS", iis.product); assertEquals("10.0", iis.version)
        assertNull(Fingerprint.parseHttpServer("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"))
    }

    @Test
    fun mysqlAndMariaHandshakes() {
        val mysql = Fingerprint.parseMysqlHandshake(byteArrayOf(0, 0, 0, 0, 10) + bytes("8.0.21") + byteArrayOf(0))!!
        assertEquals("MySQL", mysql.product); assertEquals("8.0.21", mysql.version)
        val maria = Fingerprint.parseMysqlHandshake(byteArrayOf(0, 0, 0, 0, 10) + bytes("5.5.5-10.3.25-MariaDB-1:10.3.25+maria") + byteArrayOf(0))!!
        assertEquals("MariaDB", maria.product); assertEquals("10.3.25", maria.version)
        assertNull(Fingerprint.parseMysqlHandshake(byteArrayOf(0, 0, 0, 0, 9, 1, 2))) // wrong protocol byte
    }

    @Test
    fun redisInfoAndNoauth() {
        val ok = Fingerprint.parse(ProbeKind.REDIS_INFO, 6379, bytes("$120\r\n# Server\r\nredis_version:6.0.9\r\nos:Linux\r\n"))!!
        assertEquals("Redis", ok.product); assertEquals("6.0.9", ok.version)
        val noauth = Fingerprint.parseRedisInfo("-NOAUTH Authentication required.\r\n")!!
        assertEquals("Redis", noauth.product); assertEquals("auth required", noauth.extra)
    }

    @Test
    fun probeMappingAndRequests() {
        assertEquals(ProbeKind.READ_ON_CONNECT, Fingerprint.probeFor(22))
        assertEquals(ProbeKind.HTTP_HEAD, Fingerprint.probeFor(8080))
        assertEquals(ProbeKind.NONE, Fingerprint.probeFor(445))
        assertTrue(String(Fingerprint.requestBytes(ProbeKind.HTTP_HEAD)).startsWith("HEAD / HTTP/1.0"))
        assertEquals(0, Fingerprint.requestBytes(ProbeKind.READ_ON_CONNECT).size)
    }

    @Test
    fun emptyDataIsNull() {
        assertNull(Fingerprint.parse(ProbeKind.READ_ON_CONNECT, 22, ByteArray(0)))
        assertNull(Fingerprint.parse(ProbeKind.NONE, 445, bytes("anything")))
    }
}
