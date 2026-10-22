package com.yellowowl.sentinel

/**
 * Maps a MAC address to its manufacturer via the IEEE OUI prefix (first 3 bytes). Pure and unit tested.
 * A curated subset of common consumer/enterprise vendors; the feed can extend this later.
 */
object Oui {
    /** Normalizes "AA-BB-CC-...", "aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff" to lower-case colon form, or null. */
    fun normalize(mac: String): String? {
        val hex = mac.filter { it.isLetterOrDigit() }.lowercase()
        if (hex.length != 12 || hex.any { it !in "0123456789abcdef" }) return null
        return hex.chunked(2).joinToString(":")
    }

    /** True for locally-administered / randomized MACs (2nd-least-significant bit of first octet set). */
    fun isLocallyAdministered(mac: String): Boolean {
        val norm = normalize(mac) ?: return false
        val firstOctet = norm.substring(0, 2).toInt(16)
        return firstOctet and 0x02 != 0
    }

    fun vendor(mac: String): String? {
        val norm = normalize(mac) ?: return null
        if (isLocallyAdministered(norm)) return "Randomized MAC"
        val prefix = norm.split(":").take(3).joinToString(":")
        return prefixes[prefix]
    }

    private val prefixes: Map<String, String> = mapOf(
        // Apple
        "00:1c:b3" to "Apple", "00:25:00" to "Apple", "3c:07:54" to "Apple", "a4:83:e7" to "Apple",
        "f0:18:98" to "Apple", "dc:a9:04" to "Apple", "ac:bc:32" to "Apple", "f4:f1:5a" to "Apple",
        // Samsung
        "00:12:fb" to "Samsung", "34:23:ba" to "Samsung", "5c:0a:5b" to "Samsung", "e8:50:8b" to "Samsung",
        "c8:19:f7" to "Samsung", "a0:21:95" to "Samsung",
        // Google / Nest
        "f4:f5:d8" to "Google", "f8:8f:ca" to "Google", "1c:f2:9a" to "Google", "54:60:09" to "Google",
        // Amazon
        "fc:a1:83" to "Amazon", "44:65:0d" to "Amazon", "68:37:e9" to "Amazon", "ac:63:be" to "Amazon",
        // Raspberry Pi
        "b8:27:eb" to "Raspberry Pi", "dc:a6:32" to "Raspberry Pi", "e4:5f:01" to "Raspberry Pi", "28:cd:c1" to "Raspberry Pi",
        // Espressif (ESP8266/ESP32 IoT)
        "24:0a:c4" to "Espressif (ESP)", "30:ae:a4" to "Espressif (ESP)", "a4:cf:12" to "Espressif (ESP)", "7c:9e:bd" to "Espressif (ESP)",
        // Networking gear
        "00:1a:11" to "Google (OnHub)", "18:e8:29" to "Ubiquiti", "24:a4:3c" to "Ubiquiti", "fc:ec:da" to "Ubiquiti",
        "00:05:5d" to "D-Link", "14:d6:4d" to "D-Link", "50:c7:bf" to "TP-Link", "a4:2b:b0" to "TP-Link",
        "c0:56:27" to "Belkin", "00:1d:7e" to "Cisco-Linksys", "00:25:9c" to "Cisco-Linksys",
        "00:00:0c" to "Cisco", "00:1b:0d" to "Cisco", "2c:3a:fd" to "Netgear", "a0:40:a0" to "Netgear",
        // Intel (NICs)
        "00:1b:21" to "Intel", "3c:a9:f4" to "Intel", "a0:88:b4" to "Intel", "7c:7a:91" to "Intel",
        // Printers
        "00:17:c8" to "Kyocera", "00:1b:a9" to "Brother", "3c:2a:f4" to "Brother", "00:00:48" to "Epson", "a4:5d:36" to "HP",
        // Microsoft / Sony / LG
        "00:50:f2" to "Microsoft", "7c:1e:52" to "Microsoft", "00:19:c5" to "Sony", "ac:9b:0a" to "LG Electronics"
    )
}
