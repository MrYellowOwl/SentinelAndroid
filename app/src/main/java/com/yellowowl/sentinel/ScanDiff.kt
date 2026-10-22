package com.yellowowl.sentinel

/** A compact record of one device from a scan, used as the monitoring baseline and for diffing. */
data class DeviceSnapshot(
    val ip: String,
    val mac: String? = null,
    val name: String? = null,
    val ports: List<Int> = emptyList()
) {
    /** Stable identity across scans: MAC when known (survives DHCP changes), else IP. */
    val key: String get() = mac?.lowercase() ?: ip
    val label: String get() = name?.takeIf { it.isNotBlank() } ?: ip
}

data class PortChange(val device: DeviceSnapshot, val opened: List<Int>, val closed: List<Int>)

data class ScanDiff(
    val newDevices: List<DeviceSnapshot>,
    val goneDevices: List<DeviceSnapshot>,
    val portChanges: List<PortChange>
) {
    val isEmpty: Boolean get() = newDevices.isEmpty() && goneDevices.isEmpty() && portChanges.isEmpty()
    val changeCount: Int get() = newDevices.size + goneDevices.size + portChanges.size
}

object ScanDiffer {
    fun snapshot(devices: List<DeviceResult>): List<DeviceSnapshot> = devices.map {
        DeviceSnapshot(it.ipAddress, it.mac, it.displayName.takeIf { n -> n != it.ipAddress }, it.openPorts.map { p -> p.port })
    }

    /** Compares a previous baseline with a fresh snapshot. */
    fun diff(old: List<DeviceSnapshot>, new: List<DeviceSnapshot>): ScanDiff {
        val oldByKey = old.associateBy { it.key }
        val newByKey = new.associateBy { it.key }
        val newDevices = new.filter { it.key !in oldByKey }
        val goneDevices = old.filter { it.key !in newByKey }
        val portChanges = new.mapNotNull { cur ->
            val prev = oldByKey[cur.key] ?: return@mapNotNull null
            val opened = cur.ports - prev.ports.toSet()
            val closed = prev.ports - cur.ports.toSet()
            if (opened.isEmpty() && closed.isEmpty()) null else PortChange(cur, opened.sorted(), closed.sorted())
        }
        return ScanDiff(newDevices, goneDevices, portChanges)
    }

    /** One-line summaries for notifications. */
    fun summaryLines(diff: ScanDiff): List<String> = buildList {
        diff.newDevices.forEach { add("New device: ${it.label}${it.mac?.let { m -> " ($m)" } ?: ""}") }
        diff.goneDevices.forEach { add("Device left: ${it.label}") }
        diff.portChanges.forEach { c ->
            if (c.opened.isNotEmpty()) add("${c.device.label}: new open port(s) ${c.opened.joinToString(",")}")
            if (c.closed.isNotEmpty()) add("${c.device.label}: closed port(s) ${c.closed.joinToString(",")}")
        }
    }
}
