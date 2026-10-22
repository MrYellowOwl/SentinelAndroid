package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SnmpTest {
    // --- independent BER builders/readers in the test, to cross-check Snmp's own codec ---
    private fun len(n: Int): List<Byte> =
        if (n < 0x80) listOf(n.toByte())
        else {
            val b = ArrayList<Byte>(); var v = n
            while (v > 0) { b.add(0, (v and 0xFF).toByte()); v = v ushr 8 }
            listOf((0x80 or b.size).toByte()) + b
        }

    private fun tlv(tag: Int, content: List<Byte>) = listOf(tag.toByte()) + len(content.size) + content
    private fun int(v: Int): List<Byte> {
        val b = ArrayList<Byte>(); var x = v
        if (x == 0) b.add(0) else while (x != 0) { b.add(0, (x and 0xFF).toByte()); x = x ushr 8 }
        if (b.first().toInt() and 0x80 != 0) b.add(0, 0)
        return tlv(0x02, b)
    }
    private fun octet(bytes: ByteArray) = tlv(0x04, bytes.toList())
    private fun oid(s: String): List<Byte> {
        val p = s.split('.').map { it.toLong() }
        val out = ArrayList<Byte>(); out.add((40 * p[0] + p[1]).toByte())
        for (i in 2 until p.size) {
            var v = p[i]
            if (v < 0x80) out.add(v.toByte())
            else {
                val g = ArrayList<Byte>(); g.add(0, (v and 0x7F).toByte()); v = v ushr 7
                while (v > 0) { g.add(0, ((v and 0x7F) or 0x80).toByte()); v = v ushr 7 }
                out.addAll(g)
            }
        }
        return out
    }

    private fun response(reqId: Int, varbinds: List<Pair<String, List<Byte>>>): ByteArray {
        val vbList = varbinds.flatMap { (o, value) -> tlv(0x30, tlv(0x06, oid(o)) + value) }
        val pdu = tlv(0xA2, int(reqId) + int(0) + int(0) + tlv(0x30, vbList))
        return tlv(0x30, int(0) + octet("public".toByteArray()) + pdu).toByteArray()
    }

    @Test
    fun parsesSysNameString() {
        val packet = response(42, listOf(Snmp.SYS_NAME to octet("router1".toByteArray())))
        val r = Snmp.parse(packet)!!
        assertEquals(42L, r.requestId)
        assertEquals(0, r.errorStatus)
        assertEquals(1, r.varbinds.size)
        assertEquals(Snmp.SYS_NAME, r.varbinds[0].oid)
        assertEquals("router1", r.varbinds[0].asString())
    }

    @Test
    fun parsesArpTableMacAndIp() {
        val arpOid = "${Snmp.ARP_PHYS_BASE}.2.192.168.1.50" // ifIndex=2, ip=192.168.1.50
        val mac = byteArrayOf(0xB8.toByte(), 0x27, 0xEB.toByte(), 0x11, 0x22, 0x33)
        val r = Snmp.parse(response(7, listOf(arpOid to octet(mac))))!!
        val vb = r.varbinds.single()
        assertEquals("b8:27:eb:11:22:33", vb.asMac())
        assertEquals("192.168.1.50", Snmp.ipFromArpOid(vb.oid))
        assertTrue(Snmp.oidStartsWith(vb.oid, Snmp.ARP_PHYS_BASE))
    }

    @Test
    fun parsesMultipleVarbindsAndLongOidSubids() {
        // a sub-identifier > 127 forces multi-byte base-128 encoding
        val bigOid = "1.3.6.1.4.1.9999.300.1"
        val r = Snmp.parse(response(1, listOf(
            Snmp.SYS_DESCR to octet("Linux router 5.4".toByteArray()),
            bigOid to octet("x".toByteArray())
        )))!!
        assertEquals(2, r.varbinds.size)
        assertEquals("Linux router 5.4", r.varbinds[0].asString())
        assertEquals(bigOid, r.varbinds[1].oid) // validates multi-byte subid decode
    }

    @Test
    fun nonPrintableOctetIsNotAString() {
        val r = Snmp.parse(response(1, listOf(Snmp.SYS_NAME to octet(byteArrayOf(0x01, 0x02, 0x00)))))!!
        assertNull(r.varbinds[0].asString())
    }

    @Test
    fun getRequestEncodesTheOidWeAskedFor() {
        // Build a real GET, then independently decode its OID and confirm it round-trips.
        val packet = Snmp.buildGet("public", Snmp.SYS_DESCR, 99)
        assertEquals(0x30, packet[0].toInt() and 0xFF)
        assertEquals(Snmp.SYS_DESCR, extractFirstOid(packet))
        val next = Snmp.buildGetNext("public", Snmp.ARP_PHYS_BASE, 1)
        assertEquals(Snmp.ARP_PHYS_BASE, extractFirstOid(next))
    }

    @Test
    fun ipFromArpOidRejectsGarbage() {
        assertNull(Snmp.ipFromArpOid("1.3.6"))
        assertEquals("10.0.0.1", Snmp.ipFromArpOid("1.3.6.1.2.1.4.22.1.2.5.10.0.0.1"))
    }

    @Test
    fun malformedPacketsReturnNull() {
        assertNull(Snmp.parse(byteArrayOf(0x30, 0x05, 0x02)))
        assertNull(Snmp.parse(ByteArray(0)))
    }

    // Walk the request TLV tree to the first OID and decode it with the test's own decoder.
    private fun extractFirstOid(data: ByteArray): String {
        var pos = 0
        fun readHeader(): Triple<Int, Int, Int> {
            val tag = data[pos].toInt() and 0xFF
            var p = pos + 1
            var l = data[p].toInt() and 0xFF; p += 1
            if (l and 0x80 != 0) { val c = l and 0x7F; l = 0; repeat(c) { l = (l shl 8) or (data[p].toInt() and 0xFF); p += 1 } }
            return Triple(tag, p, p + l)
        }
        // descend: SEQ -> skip int+octet -> PDU -> skip 3 ints -> SEQ(vblist) -> SEQ(vb) -> OID
        var (_, cs, _) = readHeader(); pos = cs                    // into message SEQ
        run { val (_, s, e) = readHeader(); pos = e }              // version
        run { val (_, s, e) = readHeader(); pos = e }              // community
        run { val (_, s, _) = readHeader(); pos = s }              // into PDU
        repeat(3) { val (_, _, e) = readHeader(); pos = e }        // reqId, err, errIdx
        run { val (_, s, _) = readHeader(); pos = s }              // into varbind list SEQ
        run { val (_, s, _) = readHeader(); pos = s }              // into varbind SEQ
        val (_, os, oe) = readHeader()                             // OID TLV
        val bytes = data.copyOfRange(os, oe)
        val first = bytes[0].toInt() and 0xFF
        val sb = StringBuilder().append(first / 40).append('.').append(first % 40)
        var v = 0L
        for (i in 1 until bytes.size) {
            val b = bytes[i].toInt() and 0xFF
            v = (v shl 7) or (b and 0x7F).toLong()
            if (b and 0x80 == 0) { sb.append('.').append(v); v = 0 }
        }
        return sb.toString()
    }
}
