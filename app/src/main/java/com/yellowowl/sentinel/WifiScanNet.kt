package com.yellowowl.sentinel

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.WifiManager
import android.os.Build
import androidx.core.content.ContextCompat

/** Reads nearby Wi-Fi access points via WifiManager. Requires location permission (Android's rule for Wi-Fi scans). */
object WifiScanNet {
    /** Whether the app currently holds the permission needed to read scan results. */
    fun hasPermission(context: Context): Boolean {
        val fine = ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val nearby = ContextCompat.checkSelfPermission(context, Manifest.permission.NEARBY_WIFI_DEVICES) == PackageManager.PERMISSION_GRANTED
            return fine || nearby
        }
        return fine
    }

    /** Returns the latest scan results, sorted by signal strength. Empty if unavailable. */
    fun scan(context: Context): List<WifiAp> {
        if (!hasPermission(context)) return emptyList()
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return emptyList()
        return try {
            @Suppress("DEPRECATION")
            wifi.startScan() // best-effort; Android may return cached results and throttle new scans
            wifi.scanResults.orEmpty().mapNotNull { r ->
                val bssid = r.BSSID ?: return@mapNotNull null
                val freq = r.frequency
                WifiAp(
                    ssid = r.SSID?.ifBlank { "(hidden)" } ?: "(hidden)",
                    bssid = bssid,
                    frequencyMhz = freq,
                    level = r.level,
                    security = WifiInfoUtil.security(r.capabilities ?: "")
                )
            }.sortedByDescending { it.level }
        } catch (_: SecurityException) {
            emptyList()
        } catch (_: Exception) {
            emptyList()
        }
    }
}
