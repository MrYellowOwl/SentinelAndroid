package com.yellowowl.sentinel

import android.content.Context
import android.net.wifi.WifiManager
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Persists per-network scan memory (see [SavedNetwork]). Separate from Findings on purpose: clearing
 * findings never touches this, and networks are only removed via [remove]. Survives app restarts.
 */
object NetworkStore {
    private const val FILE = "saved_networks.json"
    private val _networks = MutableStateFlow<List<SavedNetwork>>(emptyList())
    val networks: StateFlow<List<SavedNetwork>> = _networks.asStateFlow()

    @Volatile private var appContext: Context? = null

    fun init(context: Context) {
        if (appContext != null) return
        synchronized(this) {
            if (appContext != null) return
            val app = context.applicationContext
            appContext = app
            _networks.value = runCatching { NetworkCodec.decode(file(app).readText()) }.getOrDefault(emptyList())
        }
    }

    private fun file(context: Context) = File(context.filesDir, FILE)

    private fun persist(context: Context, networks: List<SavedNetwork>) {
        _networks.value = networks.sortedByDescending { it.lastSeen }
        runCatching { file(context).writeText(NetworkCodec.encode(_networks.value)) }
    }

    /** Folds a finished scan into the matching saved network (creating it if new) and persists. */
    fun recordScan(context: Context, range: LocalNetworkRange, result: NetworkScanResult) {
        val app = context.applicationContext
        init(app)
        val now = System.currentTimeMillis()
        val gateway = result.devices.firstOrNull { it.isGateway }
        val gatewayMac = gateway?.mac?.trim()?.lowercase()?.ifBlank { null }
        val wifi = currentWifi(app)
        val bssid = wifi?.bssid?.trim()?.lowercase()?.takeIf { it.isNotBlank() && it != "02:00:00:00:00:00" }
        val ssid = wifi?.ssid

        // Identity key, most-stable first: AP MAC → gateway MAC → SSID → subnet+gateway.
        val id = bssid ?: gatewayMac ?: ssid?.let { "ssid:$it" } ?: "net:${result.cidr}@${range.gatewayIp ?: "?"}"
        val label = ssid ?: range.gatewayIp ?: result.cidr

        val scanned = result.devices.map { d ->
            SavedDevice(
                mac = d.mac,
                ip = d.ipAddress,
                name = d.identity?.name ?: d.hostname,
                vendor = d.vendor,
                kind = d.kind,
                openPorts = d.openPorts.map { it.port }.sorted(),
                isGateway = d.isGateway
            )
        }

        val existing = _networks.value
        val prior = existing.firstOrNull { it.id == id }
        val updated = NetworkMerge.mergeScan(
            prior = prior, id = id, label = label, ssid = ssid, bssid = bssid,
            cidr = result.cidr, gatewayIp = range.gatewayIp, security = wifi?.security,
            scanned = scanned, now = now
        )
        persist(app, existing.filterNot { it.id == id } + updated)
    }

    /** Forget a saved network (the manual "remove" the user controls). */
    fun remove(context: Context, id: String) {
        val app = context.applicationContext
        init(app)
        persist(app, _networks.value.filterNot { it.id == id })
    }

    fun clearAll(context: Context) {
        val app = context.applicationContext
        init(app)
        persist(app, emptyList())
    }

    private data class Wifi(val ssid: String?, val bssid: String?, val security: String?)

    /** Best-effort read of the connected Wi-Fi's SSID/BSSID. Returns null when unavailable or denied. */
    @Suppress("DEPRECATION")
    private fun currentWifi(context: Context): Wifi? = runCatching {
        val wm = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? WifiManager ?: return null
        val info = wm.connectionInfo ?: return null
        // SSID comes quoted ("MyWifi"); unknown shows as <unknown ssid> without location permission.
        val raw = info.ssid?.trim('"')?.takeIf { it.isNotBlank() && !it.startsWith("<unknown") }
        Wifi(ssid = raw, bssid = info.bssid, security = null)
    }.getOrNull()
}
