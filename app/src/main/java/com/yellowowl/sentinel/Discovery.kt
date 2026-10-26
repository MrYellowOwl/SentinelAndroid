package com.yellowowl.sentinel

/**
 * Wire-format builders and parsers for the three LAN discovery protocols. Pure (no I/O) and unit tested;
 * the sockets live in [ReconNet]. These name and classify devices that no open TCP port would reveal.
 */

/** What a discovery response told us about a host. Fields are filled in as protocols report them. */
data class DeviceIdentity(
    val name: String? = null,      // friendly or host name
    val vendor: String? = null,    // manufacturer, when disclosed
    val model: String? = null,     // model / server string
    val kind: String? = null,      // rough category: Router, Printer, TV, Phone, NAS, …
    val mac: String? = null        // hardware address, when recovered (e.g. via SNMP ARP table)
) {
    fun merge(other: DeviceIdentity) = DeviceIdentity(
        name = name ?: other.name,
        vendor = vendor ?: other.vendor,
        model = model ?: other.model,
        kind = kind ?: other.kind,
        mac = mac ?: other.mac
    )

    val isEmpty: Boolean get() = name == null && vendor == null && model == null && kind == null && mac == null
}

/**
 * Scrubs a discovered name/label. Drops the Unicode replacement char (the "◆?" glyph shown when bytes
 * were decoded with the wrong charset — e.g. a NetBIOS name padded with NUL or non-ASCII bytes and read
 * as US-ASCII) and any other control characters, then trims. Returns null when nothing printable remains,
 * so a garbage name falls back to the IP instead of showing mojibake.
 */
internal fun cleanDeviceName(raw: String?): String? {
    if (raw == null) return null
    val cleaned = raw.replace('�', ' ').filter { !it.isISOControl() }.trim()
    return cleaned.ifBlank { null }
}

// ---------------------------------------------------------------- SSDP / UPnP (text over UDP 1900)

object Ssdp {
    const val MULTICAST_HOST = "239.255.255.250"
    const val PORT = 1900

    fun searchRequest(mx: Int = 2): ByteArray = (
        "M-SEARCH * HTTP/1.1\r\n" +
            "HOST: $MULTICAST_HOST:$PORT\r\n" +
            "MAN: \"ssdp:discover\"\r\n" +
            "MX: $mx\r\n" +
            "ST: ssdp:all\r\n\r\n"
        ).toByteArray(Charsets.US_ASCII)

    fun parseResponse(text: String): DeviceIdentity {
        val headers = parseHeaders(text)
        val server = headers["server"]
        val st = headers["st"].orEmpty() + " " + headers["usn"].orEmpty() + " " + server.orEmpty()
        return DeviceIdentity(
            model = server?.takeIf { it.isNotBlank() },
            kind = classify(st)
        )
    }

    /** The URL of the device description document (LOCATION header), where the rich name/model lives. */
    fun locationOf(text: String): String? =
        parseHeaders(text)["location"]?.takeIf { it.startsWith("http", ignoreCase = true) }

    private fun parseHeaders(text: String): Map<String, String> =
        text.lineSequence()
            .mapNotNull { line ->
                val i = line.indexOf(':')
                if (i <= 0) null else line.substring(0, i).trim().lowercase() to line.substring(i + 1).trim()
            }.toMap()

    /**
     * Parses a UPnP device-description XML document for the human-facing identity: friendlyName,
     * manufacturer, modelName/modelNumber and deviceType. This is where a TV reports "SmartTV 4K"
     * and a console reports its make — data the M-SEARCH headers alone don't carry.
     */
    fun parseDescription(xml: String): DeviceIdentity {
        fun tag(name: String): String? =
            Regex("<$name>(.*?)</$name>", setOf(RegexOption.IGNORE_CASE, RegexOption.DOT_MATCHES_ALL))
                .find(xml)?.groupValues?.get(1)?.let { unescape(it).trim() }?.takeIf { it.isNotBlank() }

        val friendly = tag("friendlyName")
        val manufacturer = tag("manufacturer")
        val modelName = tag("modelName")
        val modelNumber = tag("modelNumber")
        val deviceType = tag("deviceType").orEmpty()
        val model = when {
            modelName == null -> null
            modelNumber != null && !modelName.contains(modelNumber, true) -> "$modelName $modelNumber"
            else -> modelName
        }?.take(60)
        return DeviceIdentity(
            name = cleanDeviceName(friendly),
            vendor = cleanDeviceName(manufacturer),
            model = cleanDeviceName(model),
            kind = classify("$deviceType $friendly")
        )
    }

    private fun unescape(s: String): String = s
        .replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        .replace("&quot;", "\"").replace("&#39;", "'").replace("&apos;", "'")

    private fun classify(hint: String): String? = when {
        hint.contains("InternetGatewayDevice", true) || hint.contains("WANConnectionDevice", true) -> "Router"
        hint.contains("MediaRenderer", true) || hint.contains("dial-multiscreen", true) -> "TV / media"
        hint.contains("Printer", true) -> "Printer"
        hint.contains("MediaServer", true) -> "Media server"
        else -> null
    }
}

// ---------------------------------------------------------------- NetBIOS node status (UDP 137)

object NetBios {
    /** A node-status (NBSTAT) request for the wildcard name "*". */
    fun nodeStatusRequest(transactionId: Int = 0x4152): ByteArray {
        val out = ArrayList<Byte>(50)
        fun be16(v: Int) { out.add((v shr 8).toByte()); out.add(v.toByte()) }
        be16(transactionId)
        be16(0x0000) // flags
        be16(1); be16(0); be16(0); be16(0) // QD=1, AN/NS/AR=0
        // Encoded name: "*" + 15 NULs → first-level encoded to 32 bytes.
        val name = ByteArray(16).also { it[0] = '*'.code.toByte() }
        out.add(0x20) // length of encoded name
        for (b in name) {
            val hi = (b.toInt() ushr 4) and 0x0F
            val lo = b.toInt() and 0x0F
            out.add(('A'.code + hi).toByte())
            out.add(('A'.code + lo).toByte())
        }
        out.add(0x00) // end of name
        be16(0x0021) // type NBSTAT
        be16(0x0001) // class IN
        return out.toByteArray()
    }

    /** Returns the primary (unique, suffix 0x00) NetBIOS machine name, trimmed, or null. */
    fun parseNodeStatus(data: ByteArray): DeviceIdentity? {
        // Header(12) + echoed question. Question = 34-byte name + type(2) + class(2) = 38. Answer starts at 50.
        var p = 12
        // skip question name (length-prefixed labels until 0x00)
        while (p < data.size && data[p].toInt() != 0) p += (data[p].toInt() and 0xFF) + 1
        p += 1 + 4 // null terminator + qtype + qclass
        if (p + 12 > data.size) return null
        // Answer RR: name(pointer or labels) + type(2)+class(2)+ttl(4)+rdlen(2)
        if ((data[p].toInt() and 0xC0) == 0xC0) p += 2 else {
            while (p < data.size && data[p].toInt() != 0) p += (data[p].toInt() and 0xFF) + 1
            p += 1
        }
        p += 2 + 2 + 4 + 2 // type + class + ttl + rdlen
        if (p >= data.size) return null
        val count = data[p].toInt() and 0xFF; p += 1
        var workstation: String? = null
        repeat(count) {
            if (p + 18 > data.size) return@repeat
            val raw = cleanDeviceName(String(data, p, 15, Charsets.US_ASCII))
            val suffix = data[p + 15].toInt() and 0xFF
            val flags = ((data[p + 16].toInt() and 0xFF) shl 8) or (data[p + 17].toInt() and 0xFF)
            val isGroup = (flags and 0x8000) != 0
            if (suffix == 0x00 && !isGroup && workstation == null && raw != null) workstation = raw
            p += 18
        }
        return workstation?.let { DeviceIdentity(name = it, kind = "Windows/SMB") }
    }
}

// ---------------------------------------------------------------- DNS / mDNS (UDP 5353)

object MdnsDns {
    const val MULTICAST_HOST = "224.0.0.251"
    const val PORT = 5353

    const val TYPE_A = 1
    const val TYPE_NS = 2
    const val TYPE_CNAME = 5
    const val TYPE_SOA = 6
    const val TYPE_PTR = 12
    const val TYPE_MX = 15
    const val TYPE_TXT = 16
    const val TYPE_AAAA = 28
    const val TYPE_SRV = 33

    fun typeName(type: Int): String = when (type) {
        TYPE_A -> "A"; TYPE_NS -> "NS"; TYPE_CNAME -> "CNAME"; TYPE_SOA -> "SOA"
        TYPE_PTR -> "PTR"; TYPE_MX -> "MX"; TYPE_TXT -> "TXT"; TYPE_AAAA -> "AAAA"; TYPE_SRV -> "SRV"
        else -> "TYPE$type"
    }

    fun typeFor(name: String): Int = when (name.trim().uppercase()) {
        "A" -> TYPE_A; "NS" -> TYPE_NS; "CNAME" -> TYPE_CNAME; "SOA" -> TYPE_SOA
        "PTR" -> TYPE_PTR; "MX" -> TYPE_MX; "TXT" -> TYPE_TXT; "AAAA" -> TYPE_AAAA; "SRV" -> TYPE_SRV
        else -> TYPE_A
    }

    data class Record(val name: String, val type: Int, val target: String?, val ip: String?, val txt: List<String>)
    data class Message(val questions: List<String>, val answers: List<Record>)

    /**
     * A query for [name] of [type]. Set [qu] for a unicast mDNS response, or [recursionDesired] when
     * querying a normal resolver (8.8.8.8 etc.) — without the RD flag a recursive resolver returns nothing.
     */
    fun query(name: String, type: Int = TYPE_PTR, transactionId: Int = 0, qu: Boolean = false, recursionDesired: Boolean = false): ByteArray {
        val out = ArrayList<Byte>(name.length + 18)
        fun be16(v: Int) { out.add((v shr 8).toByte()); out.add(v.toByte()) }
        be16(transactionId); be16(if (recursionDesired) 0x0100 else 0x0000)
        be16(1); be16(0); be16(0); be16(0)
        for (label in name.split('.')) {
            val bytes = label.toByteArray(Charsets.US_ASCII)
            out.add(bytes.size.toByte()); out.addAll(bytes.toList())
        }
        out.add(0x00)
        be16(type); be16(if (qu) 0x8001 else 0x0001) // QU bit + class IN
        return out.toByteArray()
    }

    /** Parses a DNS/mDNS response, following name-compression pointers. Returns null on malformed input. */
    fun parse(data: ByteArray): Message? {
        if (data.size < 12) return null
        fun u16(off: Int) = ((data[off].toInt() and 0xFF) shl 8) or (data[off + 1].toInt() and 0xFF)
        val qd = u16(4); val an = u16(6)

        // name reader: returns decoded name and the offset just past the name in the record stream
        fun readName(start: Int): Pair<String, Int> {
            val labels = ArrayList<String>()
            var p = start
            var afterPointer = -1
            var guard = 0
            while (p < data.size && guard++ < 128) {
                val len = data[p].toInt() and 0xFF
                when {
                    len == 0 -> { p += 1; break }
                    (len and 0xC0) == 0xC0 -> {
                        if (p + 1 >= data.size) break
                        val ptr = ((len and 0x3F) shl 8) or (data[p + 1].toInt() and 0xFF)
                        if (afterPointer < 0) afterPointer = p + 2
                        p = ptr
                    }
                    else -> {
                        if (p + 1 + len > data.size) break
                        labels.add(String(data, p + 1, len, Charsets.UTF_8))
                        p += 1 + len
                    }
                }
            }
            return labels.joinToString(".") to (if (afterPointer >= 0) afterPointer else p)
        }

        var p = 12
        val questions = ArrayList<String>()
        repeat(qd) {
            val (name, next) = readName(p)
            questions.add(name)
            p = next + 4 // qtype + qclass
            if (p > data.size) return null
        }

        val answers = ArrayList<Record>()
        repeat(an) {
            if (p + 10 > data.size) return@repeat
            val (name, afterName) = readName(p)
            var q = afterName
            val type = u16(q); q += 2
            q += 2 + 4 // class + ttl
            val rdlen = u16(q); q += 2
            val rdStart = q
            if (rdStart + rdlen > data.size) return@repeat
            var target: String? = null; var ip: String? = null; var txt = emptyList<String>()
            when (type) {
                TYPE_A -> if (rdlen == 4) ip = (0 until 4).joinToString(".") { (data[rdStart + it].toInt() and 0xFF).toString() }
                TYPE_AAAA -> if (rdlen == 16) ip = (0 until 8).joinToString(":") {
                    "%x".format(((data[rdStart + it * 2].toInt() and 0xFF) shl 8) or (data[rdStart + it * 2 + 1].toInt() and 0xFF))
                }
                TYPE_PTR, TYPE_NS, TYPE_CNAME -> target = readName(rdStart).first
                TYPE_SOA -> target = readName(rdStart).first // primary name server (mname)
                TYPE_MX -> if (rdlen > 2) target = readName(rdStart + 2).first // 2-byte preference, then exchange
                TYPE_SRV -> if (rdlen > 6) target = readName(rdStart + 6).first // priority+weight+port, then target
                TYPE_TXT -> txt = readTxt(data, rdStart, rdlen)
            }
            answers.add(Record(name, type, target, ip, txt))
            p = rdStart + rdlen
        }
        return Message(questions, answers)
    }

    private fun readTxt(data: ByteArray, start: Int, len: Int): List<String> {
        val out = ArrayList<String>()
        var p = start
        val end = start + len
        while (p < end) {
            val l = data[p].toInt() and 0xFF
            if (p + 1 + l > end) break
            if (l > 0) out.add(String(data, p + 1, l, Charsets.UTF_8))
            p += 1 + l
        }
        return out
    }

    /** Turns mDNS answers for one host into a device identity. */
    fun identify(message: Message): DeviceIdentity {
        val names = message.answers.mapNotNull { rec ->
            when (rec.type) {
                TYPE_A -> rec.name.removeSuffix(".local").removeSuffix(".")
                TYPE_PTR, TYPE_SRV -> rec.target?.substringBefore("._")?.takeIf { it.isNotBlank() && !it.startsWith("_") }
                else -> null
            }
        }
        val txt = message.answers.flatMap { it.txt }
        val vendor = txt.firstOrNull { it.startsWith("vendor=", true) || it.startsWith("manufacturer=", true) || it.startsWith("mfg=", true) }
            ?.substringAfter('=')?.trim()
        val model = txt.firstOrNull { it.startsWith("model=", true) || it.startsWith("md=", true) || it.startsWith("ty=", true) }
            ?.substringAfter('=')?.trim()
        val services = message.answers.filter { it.type == TYPE_PTR }.mapNotNull { it.name }
        return DeviceIdentity(
            name = cleanDeviceName(names.firstOrNull { it.isNotBlank() }),
            vendor = cleanDeviceName(vendor),
            model = cleanDeviceName(model),
            kind = classifyServices(services)
        )
    }

    private fun classifyServices(services: List<String>): String? = when {
        services.any { it.contains("_ipp", true) || it.contains("_printer", true) || it.contains("_pdl-datastream", true) } -> "Printer"
        services.any { it.contains("_airplay", true) || it.contains("_googlecast", true) || it.contains("_spotify-connect", true) } -> "TV / media"
        services.any { it.contains("_smb", true) || it.contains("_afpovertcp", true) || it.contains("_nfs", true) } -> "NAS / file share"
        services.any { it.contains("_homekit", true) || it.contains("_hap", true) } -> "Smart home"
        services.any { it.contains("_companion-link", true) || it.contains("_rdlink", true) } -> "Apple device"
        else -> null
    }
}
