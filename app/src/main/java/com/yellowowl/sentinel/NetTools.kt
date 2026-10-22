package com.yellowowl.sentinel

/**
 * Pure logic for the network-utility tools (subnet math, Wake-on-LAN packet, ping-output parsing,
 * whois-server selection, device-type inference). No I/O — unit tested. Sockets live in [NetToolsNet].
 */

// ---------------------------------------------------------------- Subnet calculator

data class SubnetInfo(
    val cidr: String,
    val netmask: String,
    val wildcard: String,
    val network: String,
    val broadcast: String,
    val firstHost: String,
    val lastHost: String,
    val usableHosts: Long
)

object Subnet {
    fun calc(ip: String, prefix: Int): SubnetInfo? {
        val addr = Ipv4.parse(ip) ?: return null
        if (prefix !in 0..32) return null
        val mask = if (prefix == 0) 0L else (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
        val network = addr and mask
        val broadcast = network or (mask.inv() and 0xFFFFFFFFL)
        val total = 1L shl (32 - prefix)
        val usable = when {
            prefix >= 31 -> total   // /31 and /32 have no network/broadcast reservation in practice
            else -> total - 2
        }
        val first = if (prefix >= 31) network else network + 1
        val last = if (prefix >= 31) broadcast else broadcast - 1
        return SubnetInfo(
            cidr = "${Ipv4.format(network)}/$prefix",
            netmask = Ipv4.format(mask),
            wildcard = Ipv4.format(mask.inv() and 0xFFFFFFFFL),
            network = Ipv4.format(network),
            broadcast = Ipv4.format(broadcast),
            firstHost = Ipv4.format(first),
            lastHost = Ipv4.format(last),
            usableHosts = usable.coerceAtLeast(0)
        )
    }
}

// ---------------------------------------------------------------- Wake-on-LAN

object Wol {
    /** 6 bytes of 0xFF followed by the 6-byte MAC repeated 16 times (102 bytes), or null for a bad MAC. */
    fun magicPacket(mac: String): ByteArray? {
        val norm = Oui.normalize(mac) ?: return null
        val bytes = norm.split(":").map { it.toInt(16).toByte() }
        if (bytes.size != 6) return null
        val packet = ByteArray(6 + 16 * 6)
        for (i in 0 until 6) packet[i] = 0xFF.toByte()
        for (rep in 0 until 16) for (i in 0 until 6) packet[6 + rep * 6 + i] = bytes[i]
        return packet
    }
}

// ---------------------------------------------------------------- Ping output parsing

data class PingResult(
    val transmitted: Int,
    val received: Int,
    val lossPercent: Int,
    val avgMs: Double?
) {
    val reachable: Boolean get() = received > 0
}

object PingParse {
    /** Parses standard busybox/iputils `ping` summary output. */
    fun parse(output: String): PingResult? {
        val stats = Regex("""(\d+)\s+packets transmitted,\s*(\d+)\s*(?:packets )?received""").find(output) ?: return null
        val transmitted = stats.groupValues[1].toInt()
        val received = stats.groupValues[2].toInt()
        val loss = Regex("""(\d+)%\s*packet loss""").find(output)?.groupValues?.get(1)?.toIntOrNull()
            ?: if (transmitted > 0) ((transmitted - received) * 100 / transmitted) else 100
        // rtt min/avg/max/mdev = 1.2/3.4/5.6/0.7 ms
        val avg = Regex("""=\s*[\d.]+/([\d.]+)/""").find(output)?.groupValues?.get(1)?.toDoubleOrNull()
        return PingResult(transmitted, received, loss, avg)
    }
}

// ---------------------------------------------------------------- Whois server selection

object WhoisServers {
    private const val IANA = "whois.iana.org"
    private val byTld = mapOf(
        "com" to "whois.verisign-grs.com", "net" to "whois.verisign-grs.com",
        "org" to "whois.pir.org", "io" to "whois.nic.io", "dev" to "whois.nic.google",
        "app" to "whois.nic.google", "co" to "whois.nic.co", "us" to "whois.nic.us",
        "uk" to "whois.nic.uk", "ca" to "whois.cira.ca", "au" to "whois.auda.org.au",
        "de" to "whois.denic.de", "info" to "whois.nic.info", "biz" to "whois.nic.biz",
        "me" to "whois.nic.me", "tv" to "whois.nic.tv", "xyz" to "whois.nic.xyz"
    )

    fun forDomain(domain: String): String {
        val tld = domain.trim().trimEnd('.').substringAfterLast('.', "").lowercase()
        return byTld[tld] ?: IANA
    }
}

// ---------------------------------------------------------------- Device-type inference (Fing-style, offline)

object DeviceClassifier {
    /** Best-guess device category from vendor, open ports and any service hint. Fills in [DeviceResult.kind]. */
    fun classify(vendor: String?, openPorts: List<Int>, existingKind: String?): String? {
        if (existingKind != null) return existingKind
        val v = vendor?.lowercase().orEmpty()
        val ports = openPorts.toSet()
        return when {
            9100 in ports || 631 in ports || "brother" in v || "epson" in v || "kyocera" in v || "hp" in v && 9100 in ports -> "Printer"
            554 in ports || 8554 in ports -> "IP camera"
            32400 in ports || 8096 in ports -> "Media server"
            "raspberry" in v -> "Raspberry Pi"
            "espressif" in v -> "IoT device (ESP)"
            "ubiquiti" in v || "mikrotik" in v || "tp-link" in v || "netgear" in v || "d-link" in v || "cisco" in v -> "Router / network gear"
            445 in ports && 139 in ports -> "Windows PC / server"
            22 in ports && (80 in ports || 443 in ports) -> "Server"
            "apple" in v -> "Apple device"
            "samsung" in v || "google" in v || "amazon" in v -> "Consumer device"
            80 in ports || 443 in ports -> "Web host"
            else -> null
        }
    }
}
