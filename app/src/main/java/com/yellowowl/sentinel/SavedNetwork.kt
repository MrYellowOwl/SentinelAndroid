package com.yellowowl.sentinel

import org.json.JSONArray
import org.json.JSONObject

/**
 * Per-network scan memory — Fing-style. Each Wi-Fi/Ethernet network the user scans is remembered
 * separately with its own device list, and devices carry first-seen / last-seen / online state so the
 * history survives across scans and app restarts. This data is independent of Findings: clearing
 * findings never touches it, and networks are only removed by an explicit action.
 *
 * This file is pure (model + merge + JSON codec) so it is unit-testable; the Context-bound persistence
 * and the live Wi-Fi identity capture live in [NetworkStore].
 */
data class SavedDevice(
    val mac: String?,            // stable identity when recovered (SNMP/ARP); null → keyed by IP
    val ip: String,
    val name: String? = null,    // hostname / discovered name
    val vendor: String? = null,
    val kind: String? = null,    // Router, Printer, TV, Phone, NAS…
    val openPorts: List<Int> = emptyList(),
    val firstSeen: Long = 0L,
    val lastSeen: Long = 0L,
    val online: Boolean = true,  // seen in this network's most recent scan
    val isGateway: Boolean = false
) {
    val displayName: String get() = name?.takeIf { it.isNotBlank() } ?: ip
}

data class SavedNetwork(
    val id: String,              // stable key: bssid → ssid → gateway/cidr
    val label: String,           // display name: SSID, else gateway IP, else CIDR
    val ssid: String? = null,
    val bssid: String? = null,
    val cidr: String? = null,
    val gatewayIp: String? = null,
    val security: String? = null,
    val firstSeen: Long = 0L,
    val lastSeen: Long = 0L,
    val devices: List<SavedDevice> = emptyList()
) {
    val deviceCount: Int get() = devices.size
    val onlineCount: Int get() = devices.count { it.online }
}

/** Merges a fresh scan into a network's saved device list, preserving first-seen and offline history. */
object NetworkMerge {
    /** Devices are matched across scans by MAC when known, otherwise by IP. */
    fun deviceKey(mac: String?, ip: String): String =
        mac?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }?.let { "mac:$it" } ?: "ip:$ip"

    private fun keyOf(d: SavedDevice) = deviceKey(d.mac, d.ip)

    /**
     * Produce the updated network record. Devices present in [scanned] are marked online with
     * lastSeen=[now] (keeping their original firstSeen); devices only in [prior] are kept but marked
     * offline. Network-level firstSeen is preserved from [prior].
     */
    fun mergeScan(
        prior: SavedNetwork?,
        id: String,
        label: String,
        ssid: String?,
        bssid: String?,
        cidr: String?,
        gatewayIp: String?,
        security: String?,
        scanned: List<SavedDevice>,
        now: Long
    ): SavedNetwork {
        val priorByKey = prior?.devices?.associateBy { keyOf(it) }.orEmpty()
        val seenKeys = HashSet<String>()
        val merged = ArrayList<SavedDevice>(scanned.size + priorByKey.size)

        for (d in scanned) {
            val key = keyOf(d)
            seenKeys.add(key)
            val was = priorByKey[key]
            merged.add(
                d.copy(
                    firstSeen = was?.firstSeen?.takeIf { it > 0 } ?: now,
                    lastSeen = now,
                    online = true
                )
            )
        }
        // Keep devices from past scans that didn't answer this time, marked offline.
        for ((key, old) in priorByKey) {
            if (key !in seenKeys) merged.add(old.copy(online = false))
        }
        // Gateway first, then online before offline, then by numeric IP for a stable order.
        merged.sortWith(
            compareByDescending<SavedDevice> { it.isGateway }
                .thenByDescending { it.online }
                .thenBy { Ipv4.parse(it.ip) ?: Long.MAX_VALUE }
        )
        return SavedNetwork(
            id = id,
            label = label,
            ssid = ssid,
            bssid = bssid,
            cidr = cidr,
            gatewayIp = gatewayIp,
            security = security,
            firstSeen = prior?.firstSeen?.takeIf { it > 0 } ?: now,
            lastSeen = now,
            devices = merged
        )
    }
}

/** JSON (de)serialization for the saved-networks store. Tolerant of missing fields. */
object NetworkCodec {
    const val VERSION = 1

    fun encode(networks: List<SavedNetwork>): String {
        val arr = JSONArray()
        for (n in networks) {
            val devs = JSONArray()
            for (d in n.devices) {
                devs.put(
                    JSONObject()
                        .put("mac", d.mac ?: JSONObject.NULL)
                        .put("ip", d.ip)
                        .put("name", d.name ?: JSONObject.NULL)
                        .put("vendor", d.vendor ?: JSONObject.NULL)
                        .put("kind", d.kind ?: JSONObject.NULL)
                        .put("ports", JSONArray(d.openPorts))
                        .put("firstSeen", d.firstSeen)
                        .put("lastSeen", d.lastSeen)
                        .put("online", d.online)
                        .put("gateway", d.isGateway)
                )
            }
            arr.put(
                JSONObject()
                    .put("id", n.id)
                    .put("label", n.label)
                    .put("ssid", n.ssid ?: JSONObject.NULL)
                    .put("bssid", n.bssid ?: JSONObject.NULL)
                    .put("cidr", n.cidr ?: JSONObject.NULL)
                    .put("gatewayIp", n.gatewayIp ?: JSONObject.NULL)
                    .put("security", n.security ?: JSONObject.NULL)
                    .put("firstSeen", n.firstSeen)
                    .put("lastSeen", n.lastSeen)
                    .put("devices", devs)
            )
        }
        return JSONObject().put("version", VERSION).put("networks", arr).toString()
    }

    fun decode(json: String): List<SavedNetwork> {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return emptyList()
        val arr = root.optJSONArray("networks") ?: return emptyList()
        val out = ArrayList<SavedNetwork>(arr.length())
        for (i in 0 until arr.length()) {
            val o = arr.optJSONObject(i) ?: continue
            val id = o.optString("id")
            if (id.isBlank()) continue
            val devsArr = o.optJSONArray("devices") ?: JSONArray()
            val devices = ArrayList<SavedDevice>(devsArr.length())
            for (j in 0 until devsArr.length()) {
                val d = devsArr.optJSONObject(j) ?: continue
                val ip = d.optString("ip")
                if (ip.isBlank()) continue
                val portsArr = d.optJSONArray("ports") ?: JSONArray()
                val ports = ArrayList<Int>(portsArr.length())
                for (k in 0 until portsArr.length()) ports.add(portsArr.optInt(k))
                devices.add(
                    SavedDevice(
                        mac = d.optString("mac").ifBlank { null },
                        ip = ip,
                        name = d.optString("name").ifBlank { null },
                        vendor = d.optString("vendor").ifBlank { null },
                        kind = d.optString("kind").ifBlank { null },
                        openPorts = ports,
                        firstSeen = d.optLong("firstSeen"),
                        lastSeen = d.optLong("lastSeen"),
                        online = d.optBoolean("online", true),
                        isGateway = d.optBoolean("gateway", false)
                    )
                )
            }
            out.add(
                SavedNetwork(
                    id = id,
                    label = o.optString("label").ifBlank { id },
                    ssid = o.optString("ssid").ifBlank { null },
                    bssid = o.optString("bssid").ifBlank { null },
                    cidr = o.optString("cidr").ifBlank { null },
                    gatewayIp = o.optString("gatewayIp").ifBlank { null },
                    security = o.optString("security").ifBlank { null },
                    firstSeen = o.optLong("firstSeen"),
                    lastSeen = o.optLong("lastSeen"),
                    devices = devices
                )
            )
        }
        return out.sortedByDescending { it.lastSeen }
    }
}
