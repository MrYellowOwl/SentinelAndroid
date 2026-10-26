package com.yellowowl.sentinel

/**
 * Parser for the kernel ARP cache (`/proc/net/arp`). On Android 10+ this is sandboxed and usually
 * returns nothing for an app, but on older/rooted devices and some OEMs it still yields IP↔MAC pairs —
 * a free, local MAC source on top of the SNMP ARP walk. Pure; the file read lives in [ReconNet].
 */
object ArpTable {
    private val MAC = Regex("([0-9a-f]{2}:){5}[0-9a-f]{2}")
    private val IPV4 = Regex("""\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}""")

    /** IP → lower-case MAC for every complete, non-null entry. */
    fun parse(text: String): Map<String, String> {
        val out = LinkedHashMap<String, String>()
        for (line in text.lineSequence().drop(1)) {            // first line is the column header
            val cols = line.trim().split(Regex("\\s+"))
            if (cols.size < 4) continue
            val ip = cols[0]
            val flags = cols[2]
            val mac = cols[3].lowercase()
            if (flags == "0x0") continue                       // incomplete / unresolved
            if (mac == "00:00:00:00:00:00") continue
            if (!IPV4.matches(ip) || !MAC.matches(mac)) continue
            out[ip] = mac
        }
        return out
    }
}
