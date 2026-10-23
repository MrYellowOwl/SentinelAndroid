package com.yellowowl.sentinel

/**
 * Identifies the software behind an open port from the banner or header it returns.
 * All parsing is pure (no I/O) so it can be unit tested; the network reads live in [ReconNet].
 */
data class ServiceFingerprint(
    val product: String,
    val version: String? = null,
    val extra: String? = null
) {
    /** Human-readable label, e.g. "OpenSSH 8.2p1". */
    val display: String get() = listOfNotNull(product, version).joinToString(" ")

    /** Lower-case product key used to match against a CVE/product feed. */
    val productKey: String get() = product.lowercase().replace(" ", "_")
}

/** How to coax a banner out of a given port. */
enum class ProbeKind { READ_ON_CONNECT, HTTP_HEAD, MYSQL_HANDSHAKE, REDIS_INFO, MEMCACHED, ELASTICSEARCH, DNS_VERSION, NONE }

object Fingerprint {
    /** Ports that reveal useful version info, and how to ask. HTTPS/TLS ports are handled by the web auditor. */
    val probeByPort: Map<Int, ProbeKind> = mapOf(
        21 to ProbeKind.READ_ON_CONNECT,   // FTP
        22 to ProbeKind.READ_ON_CONNECT,   // SSH
        25 to ProbeKind.READ_ON_CONNECT,   // SMTP
        53 to ProbeKind.DNS_VERSION,       // DNS: version.bind CHAOS query (BIND/unbound)
        110 to ProbeKind.READ_ON_CONNECT,  // POP3
        143 to ProbeKind.READ_ON_CONNECT,  // IMAP
        80 to ProbeKind.HTTP_HEAD,
        8000 to ProbeKind.HTTP_HEAD,
        8008 to ProbeKind.HTTP_HEAD,
        8080 to ProbeKind.HTTP_HEAD,
        8888 to ProbeKind.HTTP_HEAD,
        5000 to ProbeKind.HTTP_HEAD,
        9100 to ProbeKind.READ_ON_CONNECT, // some printers emit PJL/banner
        3306 to ProbeKind.MYSQL_HANDSHAKE,
        6379 to ProbeKind.REDIS_INFO,
        9200 to ProbeKind.ELASTICSEARCH,   // Elasticsearch REST: GET / returns version JSON
        11211 to ProbeKind.MEMCACHED       // Memcached: "version" command (unauthenticated)
    )

    fun probeFor(port: Int): ProbeKind = probeByPort[port] ?: ProbeKind.NONE

    /** Kinds whose response spans many lines/bytes, so the reader shouldn't stop at the first newline. */
    val multiLineKinds = setOf(ProbeKind.HTTP_HEAD, ProbeKind.ELASTICSEARCH, ProbeKind.DNS_VERSION)

    /** The bytes to send to elicit a banner, or empty to just read. */
    fun requestBytes(kind: ProbeKind): ByteArray = when (kind) {
        ProbeKind.HTTP_HEAD -> "HEAD / HTTP/1.0\r\nHost: scan\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
        ProbeKind.ELASTICSEARCH -> "GET / HTTP/1.0\r\nHost: scan\r\nConnection: close\r\n\r\n".toByteArray(Charsets.US_ASCII)
        ProbeKind.REDIS_INFO -> "INFO server\r\n".toByteArray(Charsets.US_ASCII)
        ProbeKind.MEMCACHED -> "version\r\n".toByteArray(Charsets.US_ASCII)
        ProbeKind.DNS_VERSION -> dnsVersionQuery()
        else -> ByteArray(0) // READ_ON_CONNECT / MYSQL_HANDSHAKE / NONE: read the greeting the server sends first
    }

    fun parse(kind: ProbeKind, port: Int, data: ByteArray): ServiceFingerprint? {
        if (data.isEmpty()) return null
        return when (kind) {
            ProbeKind.READ_ON_CONNECT -> parseBanner(port, ascii(data))
            ProbeKind.HTTP_HEAD -> parseHttpServer(ascii(data))
            ProbeKind.MYSQL_HANDSHAKE -> parseMysqlHandshake(data)
            ProbeKind.REDIS_INFO -> parseRedisInfo(ascii(data))
            ProbeKind.MEMCACHED -> parseMemcached(ascii(data))
            ProbeKind.ELASTICSEARCH -> parseElasticsearch(ascii(data))
            ProbeKind.DNS_VERSION -> parseDnsVersion(data)
            ProbeKind.NONE -> null
        }
    }

    // ---- text banners (first line is usually enough) ----

    fun parseBanner(port: Int, banner: String): ServiceFingerprint? {
        val line = banner.lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: return null
        return when {
            line.startsWith("SSH-") -> parseSsh(line)
            port == 21 || line.startsWith("220") && line.contains("FTP", ignoreCase = true) -> parseFtp(line)
            port == 25 || port == 110 || port == 143 -> parseMailGreeting(port, line)
            else -> null
        }
    }

    /** SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.1 */
    private fun parseSsh(line: String): ServiceFingerprint? {
        val afterProto = line.removePrefix("SSH-").substringAfter('-', "").ifBlank { return null }
        val software = afterProto.substringBefore(' ').trim()
        val extra = afterProto.substringAfter(' ', "").trim().ifBlank { null }
        val (product, version) = splitProductVersion(software)
        return ServiceFingerprint(product.ifBlank { "SSH" }, version, extra)
    }

    /** 220 (vsFTPd 3.0.3) / 220 ProFTPD 1.3.5 Server */
    private fun parseFtp(line: String): ServiceFingerprint {
        val cleaned = line.removePrefix("220").trim().trim('(', ')', '-', ' ')
        val match = Regex("""([A-Za-z][A-Za-z0-9.\-]*?FTPd?|FileZilla Server|Microsoft FTP Service)[ /]?v?(\d[\w.]*)?""", RegexOption.IGNORE_CASE)
            .find(cleaned)
        return if (match != null) {
            ServiceFingerprint(match.groupValues[1], match.groupValues[2].ifBlank { null })
        } else {
            ServiceFingerprint("FTP")
        }
    }

    private fun parseMailGreeting(port: Int, line: String): ServiceFingerprint {
        val default = when (port) { 25 -> "SMTP"; 110 -> "POP3"; else -> "IMAP" }
        val product = listOf("Postfix", "Exim", "Sendmail", "Dovecot", "Microsoft ESMTP", "Exchange")
            .firstOrNull { line.contains(it, ignoreCase = true) } ?: default
        val version = Regex("""$product[ /]v?(\d[\w.]*)""", RegexOption.IGNORE_CASE).find(line)?.groupValues?.get(1)
        return ServiceFingerprint(product, version)
    }

    // ---- HTTP Server header ----

    fun parseHttpServer(response: String): ServiceFingerprint? {
        val server = response.lineSequence()
            .firstOrNull { it.startsWith("Server:", ignoreCase = true) }
            ?.substringAfter(':')?.trim() ?: return null
        // "Apache/2.4.41 (Ubuntu)" | "nginx/1.18.0" | "Microsoft-IIS/10.0" | "Jetty(9.4.44.v20210927)" | "lighttpd/1.4.55"
        val first = server.substringBefore(' ').trim()
        val extra = server.substringAfter(' ', "").trim().trim('(', ')').ifBlank { null }
        // Two shapes: "Name/version" and "Name(version)".
        val name: String
        var version: String?
        if (first.contains('(') && first.endsWith(")")) {
            name = first.substringBefore('(').trim()
            version = first.substringAfter('(').trimEnd(')').trim().ifBlank { null }
        } else {
            name = first.substringBefore('/').trim()
            version = first.substringAfter('/', "").trim().ifBlank { null }
        }
        if (name.isBlank()) return null
        // Jetty reports "9.4.44.v20210927" — keep the dotted numeric head the matcher can compare.
        version = version?.let { Regex("""\d+(\.\d+)*""").find(it)?.value ?: it }
        val product = when (name.lowercase()) {
            "apache" -> "Apache httpd"
            "apache-coyote" -> "Tomcat"       // Coyote is Tomcat's HTTP connector (version usually absent)
            "nginx" -> "nginx"
            "microsoft-iis" -> "Microsoft IIS"
            "jetty" -> "Jetty"
            "lighttpd" -> "lighttpd"
            else -> name
        }
        return ServiceFingerprint(product, version, extra)
    }

    // ---- MySQL / MariaDB initial handshake packet ----

    /** Version is an ASCII, NUL-terminated string starting at offset 5 of the greeting packet. */
    fun parseMysqlHandshake(data: ByteArray): ServiceFingerprint? {
        if (data.size < 6 || data[4].toInt() != 10) return null // protocol version 10
        val end = (5 until data.size).firstOrNull { data[it].toInt() == 0 } ?: return null
        val raw = String(data, 5, end - 5, Charsets.US_ASCII).ifBlank { return null }
        // MariaDB announces itself as "5.5.5-10.3.25-MariaDB-..." for compatibility.
        val isMaria = raw.contains("MariaDB", ignoreCase = true)
        val stripped = if (raw.startsWith("5.5.5-")) raw.removePrefix("5.5.5-") else raw
        val version = Regex("""\d+\.\d+\.\d+[\w.]*""").find(stripped)?.value
        return ServiceFingerprint(if (isMaria) "MariaDB" else "MySQL", version)
    }

    // ---- Redis INFO ----

    fun parseRedisInfo(response: String): ServiceFingerprint? {
        if (response.startsWith("-NOAUTH") || response.contains("NOAUTH", ignoreCase = true)) {
            return ServiceFingerprint("Redis", null, "auth required")
        }
        val version = response.lineSequence()
            .firstOrNull { it.startsWith("redis_version:") }
            ?.substringAfter(':')?.trim()
        return if (version != null) ServiceFingerprint("Redis", version) else null
    }

    // ---- Memcached ("version" -> "VERSION 1.6.9") ----

    fun parseMemcached(response: String): ServiceFingerprint? {
        val line = response.lineSequence().firstOrNull { it.startsWith("VERSION", ignoreCase = true) } ?: return null
        val version = line.substringAfter("VERSION", "").trim().substringBefore(' ').ifBlank { null } ?: return null
        if (Regex("""^\d""").find(version) == null) return null
        return ServiceFingerprint("Memcached", version)
    }

    // ---- Elasticsearch (GET / -> JSON body with .version.number) ----

    fun parseElasticsearch(response: String): ServiceFingerprint? {
        // Body starts after the blank line that ends the HTTP headers.
        val body = response.substringAfter("\r\n\r\n", "").ifBlank { response.substringAfter("\n\n", "") }
        val json = body.ifBlank { response }
        // Require a signal that this really is Elasticsearch, not just any JSON service.
        val looksEs = json.contains("\"cluster_name\"") || json.contains("\"lucene_version\"") ||
            json.contains("You Know, for Search") || response.contains("X-elastic-product", ignoreCase = true)
        if (!looksEs) return null
        val version = Regex(""""number"\s*:\s*"([^"]+)"""").find(json)?.groupValues?.get(1)
        return ServiceFingerprint("Elasticsearch", version)
    }

    // ---- DNS version.bind CHAOS TXT (BIND / unbound / others) ----

    /** A DNS query for "version.bind" IN class CHAOS(3), type TXT(16), framed for TCP (2-byte length prefix). */
    fun dnsVersionQuery(): ByteArray {
        val msg = ArrayList<Byte>()
        // Header: id=0x5345, flags=0x0100 (RD), qd=1, an/ns/ar=0
        val header = intArrayOf(0x53, 0x45, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        header.forEach { msg.add(it.toByte()) }
        // QNAME: version.bind
        for (label in listOf("version", "bind")) {
            msg.add(label.length.toByte())
            label.forEach { msg.add(it.code.toByte()) }
        }
        msg.add(0)                       // root label
        msg.add(0); msg.add(0x10)        // QTYPE = TXT (16)
        msg.add(0); msg.add(0x03)        // QCLASS = CH (3)
        val body = msg.toByteArray()
        return byteArrayOf((body.size ushr 8).toByte(), (body.size and 0xFF).toByte()) + body
    }

    /** Parses the TXT answer from a version.bind response (TCP-framed), returning BIND/unbound + version. */
    fun parseDnsVersion(data: ByteArray): ServiceFingerprint? {
        val b = data.map { it.toInt() and 0xFF }
        // Skip the 2-byte TCP length prefix if present, then the 12-byte header.
        var p = if (b.size > 2 && ((b[0] shl 8) or b[1]) == b.size - 2) 2 else 0
        if (b.size < p + 12) return null
        val anCount = (b[p + 6] shl 8) or b[p + 7]
        if (anCount < 1) return null
        p += 12
        // Skip the question: QNAME (labels until 0x00), then QTYPE+QCLASS (4 bytes).
        while (p < b.size && b[p] != 0) {
            if (b[p] and 0xC0 == 0xC0) { p += 1; break }  // compression pointer
            p += b[p] + 1
        }
        p += 1 + 4
        if (p >= b.size) return null
        // First answer: NAME (pointer or labels), TYPE(2), CLASS(2), TTL(4), RDLEN(2), RDATA.
        if (p < b.size && b[p] and 0xC0 == 0xC0) p += 2
        else { while (p < b.size && b[p] != 0) p += b[p] + 1; p += 1 }
        if (p + 10 > b.size) return null
        val rdLen = (b[p + 8] shl 8) or b[p + 9]
        p += 10
        if (p + rdLen > b.size || rdLen < 1) return null
        // TXT rdata: one length byte, then that many characters.
        val txtLen = b[p]
        val start = p + 1
        if (start + txtLen > b.size) return null
        val text = String(data, start, txtLen, Charsets.US_ASCII).trim()
        if (text.isBlank()) return null
        val product = when {
            text.contains("unbound", ignoreCase = true) -> "unbound"
            else -> "BIND"   // version.bind is BIND's; most other resolvers echo a plain version here too
        }
        // Clean dotted-numeric core for matching (e.g. "9.11.3"); the full string (distro suffix) stays in extra.
        val version = Regex("""\d+(\.\d+)+""").find(text)?.value
        return ServiceFingerprint(product, version, extra = text.take(60))
    }

    // ---- helpers ----

    private fun splitProductVersion(token: String): Pair<String, String?> {
        val sep = token.indexOfFirst { it == '_' || it == '/' }
        if (sep > 0) {
            val product = token.substring(0, sep)
            val version = token.substring(sep + 1).ifBlank { null }
            return product to version
        }
        // e.g. "Cisco-1.25"
        val match = Regex("""^([A-Za-z][A-Za-z.+\-]*?)[ -]?v?(\d[\w.]*)$""").find(token)
        return if (match != null) match.groupValues[1] to match.groupValues[2] else token to null
    }

    private fun ascii(data: ByteArray): String = String(data, Charsets.US_ASCII)
}
