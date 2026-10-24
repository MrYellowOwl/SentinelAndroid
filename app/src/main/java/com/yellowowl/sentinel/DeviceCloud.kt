package com.yellowowl.sentinel

import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * Opt-in online device identification. It is OFF by default and only ever runs when the user has
 * explicitly enabled it in Settings; while disabled, no device data leaves the phone. It fills in a
 * maker/model only where local discovery (UPnP/mDNS/NetBIOS/SNMP) left a blank — local always wins.
 *
 * Two sources, both read-only:
 *  - maclookup.app: MAC → manufacturer (keyless, rate-limited). Covers OUIs the bundled table misses.
 *  - Fingerbank: (MAC + hostname) → device model/type, when the user supplies their own API key.
 *
 * The HTTP calls live here; the response parsers are pure and unit-tested.
 */
object DeviceCloud {
    private const val MAX_LOOKUPS = 64   // cap per scan so a big subnet can't hammer the free tiers

    suspend fun enrich(result: NetworkScanResult, enabled: Boolean, fingerbankKey: String): NetworkScanResult {
        if (!enabled) return result
        val key = fingerbankKey.trim()
        val limiter = Semaphore(2)       // stay within free-tier request rates
        val budget = AtomicInteger(MAX_LOOKUPS)
        val enriched = withContext(Dispatchers.IO) {
            coroutineScope {
                result.devices.map { d ->
                    async {
                        val needVendor = d.vendor.isNullOrBlank()
                        val needModel = d.model.isNullOrBlank()
                        if (d.isThisDevice || (!needVendor && !needModel)) return@async d
                        val mac = d.mac?.trim()?.takeIf { it.isNotBlank() }
                        val host = (d.identity?.name ?: d.hostname)?.takeIf { it.isNotBlank() }
                        if (mac == null && host == null) return@async d
                        if (budget.getAndDecrement() <= 0) return@async d
                        var add = DeviceIdentity()
                        limiter.withPermit {
                            if (needVendor && mac != null) macVendor(mac)?.let { add = add.copy(vendor = it) }
                            if (needModel && key.isNotEmpty()) fingerbank(mac, host, key)?.let { add = add.merge(it) }
                        }
                        if (add.isEmpty) d else d.copy(identity = (d.identity ?: DeviceIdentity()).merge(add))
                    }
                }.awaitAll()
            }
        }
        return result.copy(devices = enriched)
    }

    // ---------------------------------------------------------------- MAC vendor (keyless)

    private suspend fun macVendor(mac: String): String? {
        val res = Http.get("https://api.maclookup.app/v2/macs/$mac", timeoutMillis = 6_000) ?: return null
        if (res.code !in 200..299) return null
        return parseMacVendor(res.body)
    }

    /** maclookup.app v2: {"success":true,"found":true,"company":"Samsung Electronics", …} */
    fun parseMacVendor(json: String): String? {
        val o = runCatching { JSONObject(json) }.getOrNull() ?: return null
        if (!o.optBoolean("success", false) || !o.optBoolean("found", false)) return null
        return o.optString("company").trim().ifBlank { null }
    }

    // ---------------------------------------------------------------- Fingerbank (bring-your-own key)

    private suspend fun fingerbank(mac: String?, hostname: String?, key: String): DeviceIdentity? {
        val body = JSONObject()
        if (mac != null) body.put("mac", mac)
        if (!hostname.isNullOrBlank()) body.put("hostname", hostname)
        if (body.length() == 0) return null
        val res = Http.postJson(
            "https://api.fingerbank.org/api/v2/combinations/interrogate?key=$key",
            body.toString(),
            timeoutMillis = 8_000
        ) ?: return null
        if (res.code !in 200..299) return null
        return parseFingerbank(res.body)
    }

    /** Fingerbank interrogate: {"device":{"name":"Apple/iPhone", …}, "score":…}. Keep the leaf as model. */
    fun parseFingerbank(json: String): DeviceIdentity? {
        val o = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val device = o.optJSONObject("device") ?: return null
        val name = device.optString("name").trim().ifBlank { null } ?: return null
        val leaf = name.substringAfterLast('/').trim().ifBlank { name }
        return DeviceIdentity(model = leaf, kind = fingerbankKind(name))
    }

    private fun fingerbankKind(name: String): String? {
        val n = name.lowercase()
        return when {
            n.contains("router") || n.contains("gateway") || n.contains("firewall") -> "Router"
            n.contains("printer") -> "Printer"
            n.contains("tv") || n.contains("television") || n.contains("roku") ||
                n.contains("chromecast") || n.contains("media") || n.contains("appletv") -> "TV / media"
            n.contains("iphone") || n.contains("phone") || n.contains("android") -> "Phone"
            n.contains("ipad") || n.contains("tablet") -> "Tablet"
            n.contains("xbox") || n.contains("playstation") || n.contains("nintendo") || n.contains("console") -> "Game console"
            n.contains("camera") || n.contains("webcam") -> "Camera"
            n.contains("nas") || n.contains("storage") -> "NAS / file share"
            else -> null
        }
    }
}
