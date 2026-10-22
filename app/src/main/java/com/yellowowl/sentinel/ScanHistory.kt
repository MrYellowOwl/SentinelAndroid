package com.yellowowl.sentinel

import org.json.JSONArray
import org.json.JSONObject

/** One saved scan, kept for the History screen and trend/diff comparisons. */
data class HistoryEntry(
    val at: Long,
    val type: String,          // FindingSource.NETWORK or FindingSource.WEB
    val label: String,         // CIDR for network, host for web
    val deviceCount: Int,
    val counts: Map<Severity, Int>,
    val devices: List<DeviceSnapshot> = emptyList()  // populated for network scans (enables diffing)
) {
    val issueCount: Int get() = counts.entries.filter { it.key != Severity.INFO }.sumOf { it.value }
    fun count(s: Severity): Int = counts[s] ?: 0
}

/** JSON (de)serialization for the history file. Pure + unit tested. */
object ScanHistoryCodec {
    const val MAX_ENTRIES = 60

    fun entryFromFindings(
        at: Long,
        type: String,
        label: String,
        findings: List<Finding>,
        devices: List<DeviceSnapshot> = emptyList()
    ): HistoryEntry = HistoryEntry(
        at = at,
        type = type,
        label = label,
        deviceCount = if (devices.isNotEmpty()) devices.size else 0,
        counts = FindingMerge.countBySeverity(findings),
        devices = devices
    )

    fun toJson(entries: List<HistoryEntry>): String {
        val arr = JSONArray()
        entries.take(MAX_ENTRIES).forEach { e ->
            val counts = JSONObject()
            Severity.entries.forEach { counts.put(it.name, e.count(it)) }
            val devs = JSONArray()
            e.devices.forEach { d ->
                devs.put(
                    JSONObject()
                        .put("ip", d.ip)
                        .apply { d.mac?.let { put("mac", it) }; d.name?.let { put("name", it) } }
                        .put("ports", JSONArray(d.ports))
                )
            }
            arr.put(
                JSONObject()
                    .put("at", e.at)
                    .put("type", e.type)
                    .put("label", e.label)
                    .put("deviceCount", e.deviceCount)
                    .put("counts", counts)
                    .put("devices", devs)
            )
        }
        return arr.toString()
    }

    fun parse(json: String): List<HistoryEntry> = try {
        val arr = JSONArray(json)
        (0 until arr.length()).mapNotNull { i ->
            val o = arr.optJSONObject(i) ?: return@mapNotNull null
            val counts = o.optJSONObject("counts")
            val cmap = Severity.entries.associateWith { (counts?.optInt(it.name, 0)) ?: 0 }
            val devsArr = o.optJSONArray("devices")
            val devices = if (devsArr == null) emptyList() else (0 until devsArr.length()).mapNotNull { j ->
                val d = devsArr.optJSONObject(j) ?: return@mapNotNull null
                val portsArr = d.optJSONArray("ports")
                val ports = if (portsArr == null) emptyList() else (0 until portsArr.length()).map { portsArr.optInt(it) }
                DeviceSnapshot(d.optString("ip"), d.optString("mac").ifBlank { null }, d.optString("name").ifBlank { null }, ports)
            }
            HistoryEntry(
                at = o.optLong("at"),
                type = o.optString("type"),
                label = o.optString("label"),
                deviceCount = o.optInt("deviceCount"),
                counts = cmap,
                devices = devices
            )
        }
    } catch (_: Exception) {
        emptyList()
    }

    /** Diffs a network entry against the most recent earlier network entry for the same label. */
    fun diffAgainstPrevious(entries: List<HistoryEntry>, entry: HistoryEntry): ScanDiff? {
        if (entry.type != FindingSource.NETWORK) return null
        val previous = entries.firstOrNull { it.at < entry.at && it.type == FindingSource.NETWORK && it.label == entry.label }
            ?: return null
        return ScanDiffer.diff(previous.devices, entry.devices)
    }
}
