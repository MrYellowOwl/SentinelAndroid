package com.yellowowl.sentinel

/** A nearby Wi-Fi access point from a scan. */
data class WifiAp(
    val ssid: String,
    val bssid: String,
    val frequencyMhz: Int,
    val level: Int,          // dBm
    val security: String
) {
    val channel: Int get() = WifiInfoUtil.channel(frequencyMhz)
    val band: String get() = WifiInfoUtil.band(frequencyMhz)
    val signalPercent: Int get() = WifiInfoUtil.signalPercent(level)
    val vendor: String? get() = Oui.vendor(bssid)
}

/** Pure helpers for interpreting Wi-Fi scan results. Unit tested; the scan itself lives in [WifiScanNet]. */
object WifiInfoUtil {
    fun channel(freqMhz: Int): Int = when {
        freqMhz == 2484 -> 14
        freqMhz in 2412..2472 -> (freqMhz - 2407) / 5
        freqMhz in 5160..5885 -> (freqMhz - 5000) / 5
        freqMhz in 5955..7115 -> (freqMhz - 5950) / 5   // 6 GHz (Wi-Fi 6E)
        else -> 0
    }

    fun band(freqMhz: Int): String = when {
        freqMhz < 2500 -> "2.4 GHz"
        freqMhz in 5000..5925 -> "5 GHz"
        freqMhz >= 5955 -> "6 GHz"
        else -> "?"
    }

    /** Maps RSSI (dBm) to a 0–100 bar. -50 or better = 100%, -100 = 0%. */
    fun signalPercent(dbm: Int): Int = when {
        dbm >= -50 -> 100
        dbm <= -100 -> 0
        else -> 2 * (dbm + 100)
    }

    /** Human-readable security from the capabilities string. */
    fun security(capabilities: String): String {
        val c = capabilities.uppercase()
        return when {
            "WPA3" in c || "SAE" in c -> "WPA3"
            "WPA2" in c || "RSN" in c -> "WPA2"
            "WPA" in c -> "WPA"
            "WEP" in c -> "WEP"
            else -> "Open"
        }
    }

    /** True for security a scan should flag as weak. */
    fun isWeak(security: String): Boolean = security == "Open" || security == "WEP"
}
