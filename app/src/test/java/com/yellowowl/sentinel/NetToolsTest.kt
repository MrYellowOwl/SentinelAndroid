package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class NetToolsTest {
    // ---- subnet ----
    @Test
    fun subnetSlash24() {
        val s = Subnet.calc("192.168.1.37", 24)!!
        assertEquals("192.168.1.0/24", s.cidr)
        assertEquals("255.255.255.0", s.netmask)
        assertEquals("0.0.0.255", s.wildcard)
        assertEquals("192.168.1.0", s.network)
        assertEquals("192.168.1.255", s.broadcast)
        assertEquals("192.168.1.1", s.firstHost)
        assertEquals("192.168.1.254", s.lastHost)
        assertEquals(254L, s.usableHosts)
    }

    @Test
    fun subnetSlash30And32() {
        val s30 = Subnet.calc("10.0.0.5", 30)!!
        assertEquals("10.0.0.4", s30.network)
        assertEquals("10.0.0.7", s30.broadcast)
        assertEquals(2L, s30.usableHosts)
        val s32 = Subnet.calc("10.0.0.5", 32)!!
        assertEquals("10.0.0.5", s32.network)
        assertEquals(1L, s32.usableHosts)
    }

    @Test
    fun subnetRejectsBadInput() {
        assertNull(Subnet.calc("999.1.1.1", 24))
        assertNull(Subnet.calc("10.0.0.1", 33))
    }

    // ---- WOL ----
    @Test
    fun magicPacketStructure() {
        val p = Wol.magicPacket("b8:27:eb:11:22:33")!!
        assertEquals(102, p.size)
        for (i in 0 until 6) assertEquals(0xFF.toByte(), p[i])
        // first MAC repetition
        assertEquals(0xB8.toByte(), p[6]); assertEquals(0x27.toByte(), p[7]); assertEquals(0xEB.toByte(), p[8])
        // last repetition starts at 6 + 15*6 = 96
        assertEquals(0xB8.toByte(), p[96]); assertEquals(0x33.toByte(), p[101])
        assertNull(Wol.magicPacket("not-a-mac"))
    }

    // ---- ping ----
    @Test
    fun parsesLinuxPing() {
        val out = """
            PING example.com (93.184.216.34) 56(84) bytes of data.
            64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=11.2 ms
            --- example.com ping statistics ---
            4 packets transmitted, 4 received, 0% packet loss, time 3005ms
            rtt min/avg/max/mdev = 10.9/11.4/12.1/0.4 ms
        """.trimIndent()
        val r = PingParse.parse(out)!!
        assertEquals(4, r.transmitted); assertEquals(4, r.received)
        assertEquals(0, r.lossPercent); assertEquals(11.4, r.avgMs!!, 0.001)
        assertTrue(r.reachable)
    }

    @Test
    fun parsesPacketLoss() {
        val out = "3 packets transmitted, 0 received, 100% packet loss, time 2047ms"
        val r = PingParse.parse(out)!!
        assertEquals(0, r.received); assertEquals(100, r.lossPercent)
        assertFalse(r.reachable); assertNull(r.avgMs)
    }

    @Test
    fun pingParseNullOnGarbage() {
        assertNull(PingParse.parse("command not found"))
    }

    // ---- whois ----
    @Test
    fun whoisServerByTld() {
        assertEquals("whois.verisign-grs.com", WhoisServers.forDomain("example.com"))
        assertEquals("whois.pir.org", WhoisServers.forDomain("sub.example.org"))
        assertEquals("whois.iana.org", WhoisServers.forDomain("example.unknowntld"))
    }

    // ---- classifier ----
    @Test
    fun classifierHeuristics() {
        assertEquals("Printer", DeviceClassifier.classify(null, listOf(9100, 80), null))
        assertEquals("IP camera", DeviceClassifier.classify(null, listOf(554), null))
        assertEquals("Raspberry Pi", DeviceClassifier.classify("Raspberry Pi", listOf(22), null))
        assertEquals("Router / network gear", DeviceClassifier.classify("Ubiquiti", listOf(80, 443), null))
        assertEquals("Windows PC / server", DeviceClassifier.classify(null, listOf(139, 445), null))
        assertEquals("Server", DeviceClassifier.classify(null, listOf(22, 443), null))
        assertNull(DeviceClassifier.classify(null, emptyList(), null))
        // existing kind always wins
        assertEquals("TV / media", DeviceClassifier.classify("Samsung", listOf(80), "TV / media"))
    }

    // ---- extended DNS record decoding ----
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }
    private fun encodeName(name: String): ByteArray {
        val out = ArrayList<Byte>()
        for (label in name.split('.')) { out.add(label.length.toByte()); out.addAll(label.toByteArray().toList()) }
        out.add(0); return out.toByteArray()
    }

    @Test
    fun parsesMxRecord() {
        val header = bytes(0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
        val name = encodeName("example.com")
        val rd = bytes(0, 10) + encodeName("mail.example.com") // preference 10 + exchange
        val rr = name + bytes(0, 15, 0, 1, 0, 0, 0, 10) + bytes(rd.size shr 8, rd.size and 0xFF) + rd
        val msg = MdnsDns.parse(header + rr)!!
        assertEquals(MdnsDns.TYPE_MX, msg.answers[0].type)
        assertEquals("mail.example.com", msg.answers[0].target)
        assertEquals("MX", MdnsDns.typeName(msg.answers[0].type))
    }

    @Test
    fun parsesAaaaRecord() {
        val header = bytes(0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
        val name = encodeName("v6.example.com")
        val v6 = bytes(0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
        val rr = name + bytes(0, 28, 0, 1, 0, 0, 0, 10, 0, 16) + v6
        val msg = MdnsDns.parse(header + rr)!!
        assertEquals("2001:db8:0:0:0:0:0:1", msg.answers[0].ip)
    }

    @Test
    fun parsePortSpecHandlesRangesAndLists() {
        assertEquals(listOf(22, 80, 443), NetToolsNet.parsePortSpec("22,80,443"))
        assertEquals(listOf(20, 21, 22), NetToolsNet.parsePortSpec("20-22"))
        assertEquals(listOf(80, 443, 8080), NetToolsNet.parsePortSpec("80, 443 8080"))
        assertTrue(NetToolsNet.parsePortSpec("99999,0,-5").isEmpty())
        assertEquals(5, NetToolsNet.parsePortSpec("1-100", max = 5).size)
    }

    @Test
    fun typeForMapsNames() {
        assertEquals(MdnsDns.TYPE_MX, MdnsDns.typeFor("mx"))
        assertEquals(MdnsDns.TYPE_AAAA, MdnsDns.typeFor("AAAA"))
        assertEquals(MdnsDns.TYPE_A, MdnsDns.typeFor("whatever"))
    }
}
