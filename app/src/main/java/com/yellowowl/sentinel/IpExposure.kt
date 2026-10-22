package com.yellowowl.sentinel

import org.json.JSONObject

/**
 * Pure logic for the "public-IP exposure" tool: classify an address (so we can tell the user
 * whether inbound connections are even possible), and read the public-IP info service response.
 * The network calls and the best-effort port probe live in [NetToolsNet].
 */
object IpExposure {
    enum class IpKind(val label: String) {
        PUBLIC("Public"),
        CGNAT("Carrier-grade NAT"),
        PRIVATE("Private"),
        LOOPBACK("Loopback"),
        LINK_LOCAL("Link-local"),
        UNKNOWN("Unknown")
    }

    fun classify(ip: String): IpKind {
        val v = Ipv4.parse(ip) ?: return IpKind.UNKNOWN
        return when {
            v in 0x7F000000L..0x7FFFFFFFL -> IpKind.LOOPBACK                 // 127/8
            v in 0xA9FE0000L..0xA9FEFFFFL -> IpKind.LINK_LOCAL               // 169.254/16
            v in 0x64400000L..0x647FFFFFL -> IpKind.CGNAT                    // 100.64/10
            Ipv4.isPrivate(v) -> IpKind.PRIVATE
            else -> IpKind.PUBLIC
        }
    }

    /** One line telling the user what the address kind means for inbound exposure. */
    fun verdict(kind: IpKind): String = when (kind) {
        IpKind.PUBLIC -> "You have a routable public IP. Inbound connections can reach you, so only intended ports should be open."
        IpKind.CGNAT -> "Your ISP uses carrier-grade NAT. Unsolicited inbound connections are blocked upstream — most port-forwarding won't work."
        IpKind.PRIVATE -> "This is a private address — you're likely behind another NAT and not directly reachable from the internet."
        IpKind.LOOPBACK, IpKind.LINK_LOCAL, IpKind.UNKNOWN -> "Couldn't determine a routable public address."
    }

    data class PublicIpInfo(
        val ip: String,
        val isp: String?,
        val asn: String?,
        val org: String?,
        val city: String?,
        val country: String?
    ) {
        val kind: IpKind get() = classify(ip)
        val location: String? get() = listOfNotNull(city?.ifBlank { null }, country?.ifBlank { null }).joinToString(", ").ifBlank { null }
    }

    /** Parses ip-api.com/json. Returns null on a failed lookup. */
    fun parseInfo(json: String): PublicIpInfo? = try {
        val o = JSONObject(json)
        if (o.optString("status", "success") == "fail") null
        else o.optString("query").ifBlank { null }?.let { ip ->
            PublicIpInfo(
                ip = ip,
                isp = o.optString("isp").ifBlank { null },
                asn = o.optString("as").ifBlank { null },
                org = o.optString("org").ifBlank { null },
                city = o.optString("city").ifBlank { null },
                country = o.optString("country").ifBlank { null }
            )
        }
    } catch (_: Exception) {
        null
    }

    /** Common inbound services worth checking for accidental exposure. */
    val commonInboundPorts: List<Int> = listOf(21, 22, 23, 80, 443, 445, 3306, 3389, 5900, 8080)
}
