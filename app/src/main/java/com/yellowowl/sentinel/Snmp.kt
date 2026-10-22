package com.yellowowl.sentinel

/**
 * Minimal SNMPv1 (BER/ASN.1) encoder and decoder for read-only recon. Pure — no I/O — so it is unit tested;
 * the UDP sockets live in [ReconNet].
 *
 * The high-value use is walking a router's ipNetToMediaPhysAddress table (its ARP cache), which returns the
 * MAC↔IP map for the whole LAN — data Android blocks an app from reading locally. All operations are GET /
 * GETNEXT reads with a community string; nothing is written.
 */
object Snmp {
    const val PORT = 161

    const val SYS_DESCR = "1.3.6.1.2.1.1.1.0"
    const val SYS_NAME = "1.3.6.1.2.1.1.5.0"
    /** ipNetToMediaPhysAddress: GETNEXT-walked to read the device's ARP table. */
    const val ARP_PHYS_BASE = "1.3.6.1.2.1.4.22.1.2"

    private const val TAG_INT = 0x02
    private const val TAG_OCTET = 0x04
    private const val TAG_NULL = 0x05
    private const val TAG_OID = 0x06
    private const val TAG_SEQ = 0x30
    const val PDU_GET = 0xA0
    const val PDU_GETNEXT = 0xA1
    const val PDU_RESPONSE = 0xA2

    data class VarBind(val oid: String, val type: Int, val value: ByteArray) {
        /** Printable-ASCII interpretation of an OCTET STRING, or null. */
        fun asString(): String? {
            if (type != TAG_OCTET) return null
            if (value.isEmpty()) return ""
            if (value.any { (it.toInt() and 0xFF) < 0x20 && it.toInt() != 0x09 && it.toInt() != 0x0A && it.toInt() != 0x0D }) return null
            return String(value, Charsets.US_ASCII).trim().ifBlank { null }
        }

        /** 6-byte OCTET STRING as "aa:bb:cc:dd:ee:ff", or null. */
        fun asMac(): String? {
            if (type != TAG_OCTET || value.size != 6) return null
            return value.joinToString(":") { "%02x".format(it.toInt() and 0xFF) }
        }
    }

    data class Response(val requestId: Long, val errorStatus: Int, val varbinds: List<VarBind>)

    fun buildGet(community: String, oid: String, requestId: Int, pduTag: Int = PDU_GET): ByteArray {
        val varbind = tlv(TAG_SEQ, tlv(TAG_OID, encodeOid(oid)) + tlv(TAG_NULL, emptyList()))
        val varbindList = tlv(TAG_SEQ, varbind)
        val pdu = tlv(pduTag, encodeInt(requestId.toLong()) + encodeInt(0) + encodeInt(0) + varbindList)
        val message = tlv(TAG_SEQ, encodeInt(0) + tlv(TAG_OCTET, community.toByteArray(Charsets.US_ASCII).toList()) + pdu)
        return message.toByteArray()
    }

    fun buildGetNext(community: String, oid: String, requestId: Int): ByteArray =
        buildGet(community, oid, requestId, PDU_GETNEXT)

    fun parse(data: ByteArray): Response? {
      return try {
        val reader = Reader(data)
        val seq = reader.read()
        if (seq.tag != TAG_SEQ) return null
        val inner = Reader(data, seq.contentStart, seq.contentEnd)
        inner.read() // version
        inner.read() // community
        val pdu = inner.read()
        if (pdu.tag != PDU_RESPONSE) return null
        val pduR = Reader(data, pdu.contentStart, pdu.contentEnd)
        val requestId = decodeInt(pduR.read().bytes(data))
        val errorStatus = decodeInt(pduR.read().bytes(data)).toInt()
        pduR.read() // error index
        val vbList = pduR.read()
        val vbR = Reader(data, vbList.contentStart, vbList.contentEnd)
        val binds = ArrayList<VarBind>()
        while (vbR.hasMore()) {
            val vb = vbR.read()
            if (vb.tag != TAG_SEQ) break
            val one = Reader(data, vb.contentStart, vb.contentEnd)
            val oidTlv = one.read()
            val valTlv = one.read()
            binds.add(VarBind(decodeOid(oidTlv.bytes(data)), valTlv.tag, valTlv.bytes(data)))
        }
        Response(requestId, errorStatus, binds)
      } catch (_: Exception) {
        null
      }
    }

    /** From an ipNetToMediaPhysAddress OID, the IP is the last four sub-identifiers. */
    fun ipFromArpOid(oid: String): String? {
        val parts = oid.split('.')
        if (parts.size < 4) return null
        val tail = parts.takeLast(4)
        if (tail.any { it.toIntOrNull() == null || it.toInt() !in 0..255 }) return null
        return tail.joinToString(".")
    }

    fun oidStartsWith(oid: String, base: String): Boolean = oid == base || oid.startsWith("$base.")

    // ---- BER encoding ----

    private fun encodeLength(n: Int): List<Byte> {
        if (n < 0x80) return listOf(n.toByte())
        val bytes = ArrayList<Byte>()
        var v = n
        while (v > 0) { bytes.add(0, (v and 0xFF).toByte()); v = v ushr 8 }
        return listOf((0x80 or bytes.size).toByte()) + bytes
    }

    private fun tlv(tag: Int, content: List<Byte>): List<Byte> =
        listOf(tag.toByte()) + encodeLength(content.size) + content

    private fun encodeInt(value: Long): List<Byte> {
        val bytes = ArrayList<Byte>()
        var v = value
        if (v == 0L) bytes.add(0)
        else {
            val negative = v < 0
            while (if (negative) v != -1L else v != 0L) { bytes.add(0, (v and 0xFF).toByte()); v = v shr 8 }
            val top = bytes.first().toInt() and 0x80
            if (!negative && top != 0) bytes.add(0, 0)
            if (negative && top == 0) bytes.add(0, 0xFF.toByte())
        }
        return tlv(TAG_INT, bytes)
    }

    private fun encodeOid(oid: String): List<Byte> {
        val parts = oid.split('.').map { it.toLong() }
        require(parts.size >= 2) { "OID too short" }
        val out = ArrayList<Byte>()
        out.add((40 * parts[0] + parts[1]).toByte())
        for (i in 2 until parts.size) out.addAll(base128(parts[i]))
        return out
    }

    private fun base128(value: Long): List<Byte> {
        if (value < 0x80) return listOf(value.toByte())
        val groups = ArrayList<Byte>()
        var v = value
        groups.add(0, (v and 0x7F).toByte())
        v = v ushr 7
        while (v > 0) { groups.add(0, ((v and 0x7F) or 0x80).toByte()); v = v ushr 7 }
        return groups
    }

    // ---- BER decoding ----

    private data class Tlv(val tag: Int, val contentStart: Int, val contentEnd: Int) {
        fun bytes(data: ByteArray): ByteArray = data.copyOfRange(contentStart, contentEnd)
    }

    private class Reader(private val data: ByteArray, start: Int = 0, private val end: Int = data.size) {
        private var pos = start
        fun hasMore(): Boolean = pos < end
        fun read(): Tlv {
            val tag = data[pos].toInt() and 0xFF
            var p = pos + 1
            var length = data[p].toInt() and 0xFF
            p += 1
            if (length and 0x80 != 0) {
                val count = length and 0x7F
                length = 0
                repeat(count) { length = (length shl 8) or (data[p].toInt() and 0xFF); p += 1 }
            }
            val contentStart = p
            val contentEnd = p + length
            pos = contentEnd
            return Tlv(tag, contentStart, contentEnd)
        }
    }

    private fun decodeInt(bytes: ByteArray): Long {
        if (bytes.isEmpty()) return 0
        var v = if (bytes[0].toInt() and 0x80 != 0) -1L else 0L
        for (b in bytes) v = (v shl 8) or (b.toLong() and 0xFF)
        return v
    }

    private fun decodeOid(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val out = StringBuilder()
        val first = bytes[0].toInt() and 0xFF
        out.append(first / 40).append('.').append(first % 40)
        var value = 0L
        for (i in 1 until bytes.size) {
            val b = bytes[i].toInt() and 0xFF
            value = (value shl 7) or (b and 0x7F).toLong()
            if (b and 0x80 == 0) { out.append('.').append(value); value = 0 }
        }
        return out.toString()
    }
}
