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
        assertEquals(ProbeKind.NONE, Fingerprint.probeFor(1234))
        assertEquals(ProbeKind.MEMCACHED, Fingerprint.probeFor(11211))
        assertEquals(ProbeKind.ELASTICSEARCH, Fingerprint.probeFor(9200))
        assertEquals(ProbeKind.DNS_VERSION, Fingerprint.probeFor(53))
        assertTrue(String(Fingerprint.requestBytes(ProbeKind.HTTP_HEAD)).startsWith("HEAD / HTTP/1.0"))
        assertEquals("version\r\n", String(Fingerprint.requestBytes(ProbeKind.MEMCACHED)))
        assertEquals(0, Fingerprint.requestBytes(ProbeKind.READ_ON_CONNECT).size)
    }

    @Test
    fun jettyAndLighttpdAndCoyote() {
        val jetty = Fingerprint.parseHttpServer("HTTP/1.1 200 OK\r\nServer: Jetty(9.4.44.v20210927)\r\n")!!
        assertEquals("Jetty", jetty.product); assertEquals("9.4.44", jetty.version)  // dotted numeric head only
        assertEquals("jetty", jetty.productKey)
        val lighttpd = Fingerprint.parseHttpServer("HTTP/1.1 200 OK\r\nServer: lighttpd/1.4.55\r\n")!!
        assertEquals("lighttpd", lighttpd.product); assertEquals("1.4.55", lighttpd.version)
        val coyote = Fingerprint.parseHttpServer("HTTP/1.1 200 OK\r\nServer: Apache-Coyote/1.1\r\n")!!
        assertEquals("Tomcat", coyote.product); assertEquals("tomcat", coyote.productKey)
    }

    @Test
    fun memcachedVersion() {
        val mc = Fingerprint.parse(ProbeKind.MEMCACHED, 11211, bytes("VERSION 1.6.9\r\n"))!!
        assertEquals("Memcached", mc.product); assertEquals("1.6.9", mc.version); assertEquals("memcached", mc.productKey)
        assertNull(Fingerprint.parseMemcached("ERROR\r\n"))
    }

    @Test
    fun elasticsearchVersion() {
        val body = """{"name":"node-1","cluster_name":"es","version":{"number":"7.10.0","lucene_version":"8.7.0"},"tagline":"You Know, for Search"}"""
        val es = Fingerprint.parse(ProbeKind.ELASTICSEARCH, 9200, bytes("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n$body"))!!
        assertEquals("Elasticsearch", es.product); assertEquals("7.10.0", es.version); assertEquals("elasticsearch", es.productKey)
        // Plain JSON that isn't Elasticsearch is not claimed.
        assertNull(Fingerprint.parseElasticsearch("HTTP/1.1 200 OK\r\n\r\n{\"status\":\"ok\"}"))
    }

    @Test
    fun dnsVersionBind() {
        // Build a version.bind CHAOS TXT response: header, echoed question, one TXT answer "9.11.3-1ubuntu1".
        val txt = "9.11.3-1ubuntu1"
        val msg = ArrayList<Int>()
        msg += listOf(0x53, 0x45, 0x84, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00) // header, an=1
        msg += listOf(7) + "version".map { it.code } + listOf(4) + "bind".map { it.code } + listOf(0)
        msg += listOf(0x00, 0x10, 0x00, 0x03)          // QTYPE TXT, QCLASS CH
        msg += listOf(0xC0, 0x0C)                        // answer name pointer
        msg += listOf(0x00, 0x10, 0x00, 0x03)           // TYPE TXT, CLASS CH
        msg += listOf(0x00, 0x00, 0x00, 0x00)           // TTL
        msg += listOf(0x00, txt.length + 1)             // RDLENGTH
        msg += listOf(txt.length) + txt.map { it.code } // TXT: len + text
        val body = msg.map { it.toByte() }.toByteArray()
        val framed = byteArrayOf((body.size ushr 8).toByte(), (body.size and 0xFF).toByte()) + body

        val fp = Fingerprint.parse(ProbeKind.DNS_VERSION, 53, framed)!!
        assertEquals("BIND", fp.product); assertEquals("9.11.3", fp.version); assertEquals("bind", fp.productKey)
        assertNull(Fingerprint.parseDnsVersion(byteArrayOf(0, 2, 0, 0))) // too short / no answers
    }

    @Test
    fun dnsVersionQueryIsWellFormed() {
        val q = Fingerprint.dnsVersionQuery()
        val len = ((q[0].toInt() and 0xFF) shl 8) or (q[1].toInt() and 0xFF)
        assertEquals(q.size - 2, len)                              // TCP length prefix matches body
        assertEquals(0x03, q[q.size - 1].toInt())                  // QCLASS = CHAOS
        assertTrue(String(q, Charsets.US_ASCII).contains("version"))
        assertTrue(String(q, Charsets.US_ASCII).contains("bind"))
    }

    @Test
    fun emptyDataIsNull() {
        assertNull(Fingerprint.parse(ProbeKind.READ_ON_CONNECT, 22, ByteArray(0)))
        assertNull(Fingerprint.parse(ProbeKind.NONE, 445, bytes("anything")))
    }
}
