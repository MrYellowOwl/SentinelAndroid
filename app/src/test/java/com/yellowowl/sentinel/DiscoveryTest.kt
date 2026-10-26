package com.yellowowl.sentinel

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DiscoveryTest {
    private fun bytes(vararg v: Int) = ByteArray(v.size) { v[it].toByte() }

    // ---- SSDP ----

    @Test
    fun ssdpSearchRequestIsWellFormed() {
        val req = String(Ssdp.searchRequest())
        assertTrue(req.startsWith("M-SEARCH * HTTP/1.1"))
        assertTrue(req.contains("MAN: \"ssdp:discover\""))
        assertTrue(req.contains("239.255.255.250:1900"))
    }

    @Test
    fun ssdpResponseClassifiesRouterAndKeepsServer() {
        val id = Ssdp.parseResponse(
            "HTTP/1.1 200 OK\r\nSERVER: Linux/3.14 UPnP/1.0 MiniUPnPd/1.9\r\n" +
                "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
        )
        assertEquals("Router", id.kind)
        assertEquals("Linux/3.14 UPnP/1.0 MiniUPnPd/1.9", id.model)
    }

    @Test
    fun ssdpClassifiesCast() {
        val id = Ssdp.parseResponse("HTTP/1.1 200 OK\r\nST: urn:dial-multiscreen-org:service:dial:1\r\n\r\n")
        assertEquals("TV / media", id.kind)
    }

    @Test
    fun ssdpExtractsLocationHeader() {
        val loc = Ssdp.locationOf(
            "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\n" +
                "LOCATION: http://10.0.0.177:52323/dmr.xml\r\nST: urn:schemas-upnp-org:device:MediaRenderer:1\r\n\r\n"
        )
        assertEquals("http://10.0.0.177:52323/dmr.xml", loc)
        assertNull(Ssdp.locationOf("HTTP/1.1 200 OK\r\nST: ssdp:all\r\n\r\n"))
    }

    @Test
    fun ssdpParsesDescriptionForFriendlyNameAndModel() {
        val xml = """
            <?xml version="1.0"?>
            <root xmlns="urn:schemas-upnp-org:device-1-0"><device>
              <deviceType>urn:schemas-upnp-org:device:MediaRenderer:1</deviceType>
              <friendlyName>Living Room TV</friendlyName>
              <manufacturer>Samsung Electronics</manufacturer>
              <modelName>UN55 Smart TV</modelName>
              <modelNumber>4K</modelNumber>
            </device></root>
        """.trimIndent()
        val id = Ssdp.parseDescription(xml)
        assertEquals("Living Room TV", id.name)
        assertEquals("Samsung Electronics", id.vendor)
        assertEquals("UN55 Smart TV 4K", id.model)
        assertEquals("TV / media", id.kind)
    }

    @Test
    fun ssdpDescriptionUnescapesAndSkipsRedundantModelNumber() {
        val xml = "<device><friendlyName>Bob&apos;s Xbox</friendlyName>" +
            "<manufacturer>Microsoft</manufacturer><modelName>Xbox Series X</modelName>" +
            "<modelNumber>Series X</modelNumber></device>"
        val id = Ssdp.parseDescription(xml)
        assertEquals("Bob's Xbox", id.name)
        assertEquals("Microsoft", id.vendor)
        assertEquals("Xbox Series X", id.model) // modelNumber already contained, not appended
    }

    // ---- NetBIOS ----

    @Test
    fun netbiosRequestEncodesWildcardName() {
        val req = NetBios.nodeStatusRequest()
        assertEquals(50, req.size)
        assertEquals(0x20, req[12].toInt() and 0xFF) // encoded-name length
        // '*' = 0x2A → nibbles 2,10 → 'C','K'
        assertEquals('C'.code, req[13].toInt() and 0xFF)
        assertEquals('K'.code, req[14].toInt() and 0xFF)
        assertEquals(0x21, req[req.size - 3].toInt() and 0xFF) // NBSTAT type low byte
    }

    @Test
    fun cleanDeviceNameStripsReplacementAndControlChars() {
        assertEquals("LAPTOP", cleanDeviceName("LAPTOP\u0000\u0000"))      // NUL padding
        assertEquals("LAPTOP", cleanDeviceName("LAPTOP��"))      // replacement glyphs
        assertEquals("LAP TOP", cleanDeviceName("LAP�TOP"))           // embedded → space
        assertNull(cleanDeviceName("���"))                  // all garbage → null
        assertNull(cleanDeviceName(""))
        assertNull(cleanDeviceName(null))
        assertEquals("café-tv", cleanDeviceName("café-tv"))               // keep legit Unicode
    }

    @Test
    fun netbiosScrubsNonAsciiPaddedName() {
        val header = bytes(0x41, 0x52, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0)
        val qname = ByteArray(34).also { it[0] = 0x20 }
        val question = qname + bytes(0x00, 0x21, 0x00, 0x01)
        // Name "PC-1" followed by NUL padding (not spaces) + a stray high byte — would show as ◆? raw.
        fun badEntry(): ByteArray {
            val name = ByteArray(15)
            "PC-1".toByteArray(Charsets.US_ASCII).copyInto(name)
            name[5] = 0xE9.toByte()   // stray non-ASCII byte in the padding region
            return name + bytes(0x00, 0x04, 0x00)   // suffix 0x00 (workstation), flags
        }
        val answerHeader = bytes(0xC0, 0x0C, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
        val packet = header + question + answerHeader + (bytes(1) + badEntry())
        val id = NetBios.parseNodeStatus(packet)!!
        assertEquals("PC-1", id.name)       // scrubbed, not mojibake
        assertEquals("Windows/SMB", id.kind)
    }

    @Test
    fun netbiosParsesUniqueMachineName() {
        val header = bytes(0x41, 0x52, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0)
        val qname = ByteArray(34).also { it[0] = 0x20 } // len + 32 encoded + trailing null already zero
        val question = qname + bytes(0x00, 0x21, 0x00, 0x01)
        fun nameEntry(name: String, suffix: Int, group: Boolean): ByteArray {
            val padded = name.padEnd(15).substring(0, 15).toByteArray(Charsets.US_ASCII)
            val flags = if (group) 0x8000 else 0x0400
            return padded + bytes(suffix, (flags shr 8) and 0xFF, flags and 0xFF)
        }
        val answerHeader = bytes(0xC0, 0x0C, 0x00, 0x21, 0x00, 0x01, 0, 0, 0, 0, 0, 0)
        val rdata = bytes(2) + nameEntry("WORKGROUP", 0x00, true) + nameEntry("LIVINGROOM-PC", 0x00, false)
        val packet = header + question + answerHeader + rdata
        val id = NetBios.parseNodeStatus(packet)!!
        assertEquals("LIVINGROOM-PC", id.name)
        assertEquals("Windows/SMB", id.kind)
    }

    // ---- DNS / mDNS ----

    private fun encodeName(name: String): ByteArray {
        val out = ArrayList<Byte>()
        for (label in name.split('.')) { out.add(label.length.toByte()); out.addAll(label.toByteArray().toList()) }
        out.add(0)
        return out.toByteArray()
    }

    @Test
    fun dnsQueryRoundTripsThroughParser() {
        val q = MdnsDns.query("_services._dns-sd._udp.local", MdnsDns.TYPE_PTR)
        val msg = MdnsDns.parse(q)!!
        assertEquals(listOf("_services._dns-sd._udp.local"), msg.questions)
        assertTrue(msg.answers.isEmpty())
    }

    @Test
    fun dnsParsesARecord() {
        val header = bytes(0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
        val name = encodeName("printer.local")
        val rr = name + bytes(0, 1, 0, 1, 0, 0, 0, 10, 0, 4, 192, 168, 1, 50)
        val msg = MdnsDns.parse(header + rr)!!
        assertEquals(1, msg.answers.size)
        assertEquals("192.168.1.50", msg.answers[0].ip)
        assertEquals("printer.local", msg.answers[0].name)
        assertEquals("printer", MdnsDns.identify(msg).name)
    }

    @Test
    fun dnsFollowsCompressionPointerInPtr() {
        // Question at offset 12 names "_ipp._tcp.local"; PTR answer target uses a pointer back to it.
        val header = bytes(0, 0, 0x84, 0, 0, 1, 0, 1, 0, 0, 0, 0)
        val qname = encodeName("_ipp._tcp.local")
        val question = qname + bytes(0, 12, 0, 1)
        val answerName = bytes(0xC0, 0x0C) // pointer to offset 12
        // rdata: "Office Printer" label then pointer to _ipp._tcp.local at offset 12
        val target = byteArrayOf(14) + "Office Printer".toByteArray() + bytes(0xC0, 0x0C)
        val rr = answerName + bytes(0, 12, 0, 1, 0, 0, 0, 10) + bytes((target.size shr 8), target.size and 0xFF) + target
        val msg = MdnsDns.parse(header + question + rr)!!
        assertEquals("_ipp._tcp.local", msg.questions[0])
        assertEquals("Office Printer._ipp._tcp.local", msg.answers[0].target)
        assertEquals("Printer", MdnsDns.identify(msg).kind)
    }

    @Test
    fun dnsParsesTxtVendorModel() {
        val header = bytes(0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0)
        val name = encodeName("tv.local")
        fun txt(s: String) = byteArrayOf(s.length.toByte()) + s.toByteArray()
        val rd = txt("vendor=Acme") + txt("model=SmartTV9000")
        val rr = name + bytes(0, 16, 0, 1, 0, 0, 0, 10) + bytes((rd.size shr 8), rd.size and 0xFF) + rd
        val id = MdnsDns.identify(MdnsDns.parse(header + rr)!!)
        assertEquals("Acme", id.vendor)
        assertEquals("SmartTV9000", id.model)
    }

    @Test
    fun malformedInputReturnsNull() {
        assertNull(MdnsDns.parse(bytes(1, 2, 3)))
    }

    @Test
    fun identityMergePrefersExisting() {
        val a = DeviceIdentity(name = "A", kind = null)
        val b = DeviceIdentity(name = "B", kind = "Router")
        assertEquals("A", a.merge(b).name)
        assertEquals("Router", a.merge(b).kind)
        assertTrue(DeviceIdentity().isEmpty)
    }
}
