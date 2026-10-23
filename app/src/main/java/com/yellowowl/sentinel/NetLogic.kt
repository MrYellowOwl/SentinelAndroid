package com.yellowowl.sentinel

import java.net.ConnectException
import java.net.SocketTimeoutException

/** IPv4 helpers. Addresses are held as unsigned 32-bit values in a Long. */
object Ipv4 {
    fun fromBytes(bytes: ByteArray): Long {
        require(bytes.size == 4) { "Not an IPv4 address." }
        return ((bytes[0].toLong() and 0xFF) shl 24) or
            ((bytes[1].toLong() and 0xFF) shl 16) or
            ((bytes[2].toLong() and 0xFF) shl 8) or
            (bytes[3].toLong() and 0xFF)
    }

    fun toBytes(value: Long): ByteArray =
        byteArrayOf((value shr 24).toByte(), (value shr 16).toByte(), (value shr 8).toByte(), value.toByte())

    fun parse(text: String): Long? {
        val parts = text.trim().split(".")
        if (parts.size != 4) return null
        var value = 0L
        for (part in parts) {
            if (part.isEmpty() || part.length > 3 || part.any { !it.isDigit() }) return null
            val octet = part.toInt()
            if (octet > 255) return null
            value = (value shl 8) or octet.toLong()
        }
        return value
    }

    fun format(value: Long): String = listOf(24, 16, 8, 0)
        .joinToString(".") { shift -> ((value shr shift) and 0xFF).toString() }

    /** The in-addr.arpa PTR name for a dotted IPv4, e.g. 192.168.1.5 → 5.1.168.192.in-addr.arpa. */
    fun reverseDnsName(ip: String): String? {
        val v = parse(ip) ?: return null
        return (0..3).joinToString(".") { i -> ((v shr (8 * i)) and 0xFF).toString() } + ".in-addr.arpa"
    }

    /** RFC 1918 private ranges: 10/8, 172.16/12, 192.168/16. */
    fun isPrivate(value: Long): Boolean =
        value in 0x0A000000L..0x0AFFFFFFL ||
            value in 0xAC100000L..0xAC1FFFFFL ||
            value in 0xC0A80000L..0xC0A8FFFFL

    /**
     * Works out the scan range for the phone's address. Networks larger than /24 are limited to the
     * phone's own /24 slice so traffic stays bounded. Returns null for public or unusable addresses.
     */
    fun scanRange(phoneIp: Long, prefixLength: Int, gatewayIp: String? = null): LocalNetworkRange? {
        if (!isPrivate(phoneIp) || prefixLength !in 1..32) return null
        val effectivePrefix = maxOf(24, prefixLength)
        if (effectivePrefix > 30) return null
        val mask = (0xFFFFFFFFL shl (32 - effectivePrefix)) and 0xFFFFFFFFL
        val network = phoneIp and mask
        val broadcast = network + (1L shl (32 - effectivePrefix)) - 1
        return LocalNetworkRange(
            cidr = "${format(network)}/$effectivePrefix",
            phoneIp = format(phoneIp),
            firstHost = network + 1,
            lastHost = broadcast - 1,
            prefixLength = effectivePrefix,
            gatewayIp = gatewayIp
        )
    }
}

enum class ProbeResult { OPEN, REFUSED, NO_RESPONSE }

object ProbeClassifier {
    /**
     * A refused connection (TCP RST) proves a device answered at that address, even though the port is closed.
     * Timeouts and "no route to host" mean nothing answered.
     */
    fun classifyFailure(error: Throwable): ProbeResult {
        if (error is SocketTimeoutException) return ProbeResult.NO_RESPONSE
        val message = error.message.orEmpty()
        val refused = message.contains("ECONNREFUSED") || message.contains("Connection refused", ignoreCase = true)
        return if (error is ConnectException && refused) ProbeResult.REFUSED else ProbeResult.NO_RESPONSE
    }
}

data class PortRisk(val severity: Severity, val why: String, val fix: String)

/** How wide the service scan goes. More ports = more thorough but slower. */
enum class ScanProfile(val label: String, val blurb: String) {
    FAST("Fast", "~15 ports"),
    NORMAL("Normal", "~28 ports"),
    THOROUGH("Thorough", "~110 ports");

    companion object {
        fun parse(value: String?): ScanProfile = entries.firstOrNull { it.name == value } ?: NORMAL
    }
}

object PortCatalog {
    /** Ports tried (in order) to decide whether a device is present. 62078 = iPhone/iPad sync, 8008 = Chromecast. */
    val discoveryPorts = listOf(80, 443, 22, 445, 62078, 8008, 8080, 3389, 9100, 53)

    val scanPorts = listOf(
        21, 22, 23, 53, 80, 135, 139, 443, 445, 554, 631, 1433, 1883, 2375, 3306, 3389,
        5000, 5432, 5900, 6379, 8000, 8008, 8080, 8443, 8888, 9100, 9200, 11211, 27017, 62078
    )

    private val fastPorts = listOf(21, 22, 23, 53, 80, 139, 443, 445, 3306, 3389, 5900, 8080, 8443, 62078, 8008)

    // Common additions for a thorough sweep (nmap-top-ports style), merged with [scanPorts].
    private val thoroughExtras = listOf(
        25, 37, 42, 79, 88, 106, 110, 111, 113, 119, 123, 143, 161, 179, 199, 389, 427, 465,
        513, 514, 515, 543, 544, 548, 587, 625, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1110,
        1234, 1433, 1521, 1723, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3260, 3690, 4444,
        4567, 4899, 5001, 5009, 5051, 5060, 5101, 5190, 5357, 5555, 5601, 5631, 5666, 5985, 6000,
        6001, 6646, 6667, 7000, 7070, 7777, 8081, 8089, 8181, 8200, 8291, 8333, 8530, 8649, 9000,
        9001, 9090, 9200, 9999, 10000, 11211, 32768, 49152, 49153, 49154
    )

    fun scanPortsFor(profile: ScanProfile): List<Int> = when (profile) {
        ScanProfile.FAST -> fastPorts
        ScanProfile.NORMAL -> scanPorts
        ScanProfile.THOROUGH -> (scanPorts + thoroughExtras).distinct().sorted()
    }

    private val names = mapOf(
        21 to "FTP", 22 to "SSH", 23 to "Telnet", 53 to "DNS", 80 to "HTTP", 135 to "MS RPC",
        139 to "NetBIOS", 443 to "HTTPS", 445 to "SMB file sharing", 554 to "RTSP camera stream",
        631 to "IPP printing", 1433 to "SQL Server", 1883 to "MQTT", 2375 to "Docker API",
        3306 to "MySQL", 3389 to "Remote Desktop", 5000 to "Web/admin service", 5432 to "PostgreSQL",
        5900 to "VNC", 6379 to "Redis", 8000 to "HTTP alternate", 8008 to "Cast/HTTP alternate",
        8080 to "HTTP alternate", 8443 to "HTTPS alternate", 8888 to "HTTP alternate",
        9100 to "Raw printing", 27017 to "MongoDB", 62078 to "Apple device sync"
    )

    private val extraNames = mapOf(
        25 to "SMTP", 110 to "POP3", 111 to "RPCbind", 123 to "NTP", 143 to "IMAP", 161 to "SNMP",
        389 to "LDAP", 465 to "SMTPS", 548 to "AFP", 587 to "SMTP submission", 873 to "rsync",
        993 to "IMAPS", 995 to "POP3S", 1521 to "Oracle DB", 1723 to "PPTP VPN", 1900 to "UPnP/SSDP",
        2049 to "NFS", 3128 to "Squid proxy", 5060 to "SIP", 5601 to "Kibana", 5985 to "WinRM",
        6000 to "X11", 8081 to "HTTP alternate", 8181 to "HTTP alternate", 9000 to "HTTP/admin",
        9090 to "HTTP/admin", 9200 to "Elasticsearch", 10000 to "Webmin", 11211 to "Memcached",
        8291 to "MikroTik RouterOS"
    )

    fun serviceName(port: Int): String = names[port] ?: extraNames[port] ?: "Unknown"

    private val risks = mapOf(
        23 to PortRisk(
            Severity.HIGH,
            "Telnet sends usernames, passwords and commands in plain text.",
            "Turn Telnet off and use SSH instead. If the device can't disable it, isolate it on a separate network."
        ),
        2375 to PortRisk(
            Severity.HIGH,
            "An unauthenticated Docker API gives full control of the host to anyone who can reach it.",
            "Bind Docker to a local socket only, or require TLS client certificates on port 2376."
        ),
        5900 to PortRisk(
            Severity.HIGH,
            "VNC is often set up with weak or no passwords and usually isn't encrypted.",
            "Disable VNC if unused; otherwise require a strong password and reach it only over a VPN or SSH tunnel."
        ),
        21 to PortRisk(
            Severity.MEDIUM,
            "FTP sends credentials and files unencrypted.",
            "Replace FTP with SFTP or FTPS, or disable it if nothing depends on it."
        ),
        445 to PortRisk(
            Severity.MEDIUM,
            "SMB file sharing is a common target for worms and credential attacks.",
            "Share only what's needed, disable SMBv1, keep the device patched and require strong passwords."
        ),
        3389 to PortRisk(
            Severity.MEDIUM,
            "Remote Desktop is heavily targeted by password-guessing attacks.",
            "Enable Network Level Authentication, use strong passwords or MFA, and never forward it to the internet."
        ),
        1433 to PortRisk(Severity.MEDIUM, "A database server is reachable from the LAN.", DB_FIX),
        3306 to PortRisk(Severity.MEDIUM, "A database server is reachable from the LAN.", DB_FIX),
        5432 to PortRisk(Severity.MEDIUM, "A database server is reachable from the LAN.", DB_FIX),
        27017 to PortRisk(Severity.MEDIUM, "A database server is reachable from the LAN.", DB_FIX),
        6379 to PortRisk(
            Severity.MEDIUM,
            "Redis has no password by default and can be abused to run commands.",
            "Bind Redis to localhost or a trusted interface and set requirepass / ACLs."
        ),
        9200 to PortRisk(
            Severity.HIGH,
            "Elasticsearch has no authentication in its default/open setup, so anyone who can reach it can read and delete indices.",
            "Enable the built-in security (authentication + TLS), bind it to localhost or a trusted interface, and never expose it directly."
        ),
        11211 to PortRisk(
            Severity.HIGH,
            "Memcached has no authentication and, if reachable over UDP, is abused for large reflection/amplification DDoS attacks.",
            "Bind Memcached to localhost, disable the UDP listener (-U 0), and firewall the port off from untrusted networks."
        ),
        1883 to PortRisk(
            Severity.LOW,
            "MQTT brokers often allow anonymous clients to read and publish smart-home messages.",
            "Disable anonymous access and use username/password or TLS (port 8883)."
        ),
        139 to PortRisk(
            Severity.LOW,
            "Legacy NetBIOS file sharing is enabled.",
            "Disable NetBIOS over TCP/IP if nothing on the network needs it."
        )
    )

    fun riskFor(port: Int): PortRisk? = risks[port]
}

private const val DB_FIX =
    "Make sure the database requires authentication, listens only where needed, and is never forwarded to the internet."

object NetworkFindings {
    fun from(result: NetworkScanResult): List<Finding> = result.devices.flatMap { device ->
        val label = if (device.displayName != device.ipAddress) "${device.displayName} (${device.ipAddress})" else device.ipAddress
        device.openPorts.mapNotNull { port ->
            val risk = PortCatalog.riskFor(port.port) ?: return@mapNotNull null
            val versionNote = port.fingerprint?.let { " Identified as ${it.display}." }.orEmpty()
            Finding(
                title = "${port.label} open on $label",
                severity = risk.severity,
                source = FindingSource.NETWORK,
                scope = result.cidr,
                target = "${device.ipAddress}:${port.port}",
                details = "${risk.why} The port accepted a connection from this phone.$versionNote An open port isn't proof of a vulnerability; check how the service is configured.",
                remediation = risk.fix
            )
        }
    }
}
