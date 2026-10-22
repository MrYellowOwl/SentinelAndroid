package com.yellowowl.sentinel

/**
 * Pure helpers for user-assigned device names. A nickname is keyed the same way the diff engine
 * keys a device — MAC when known (survives DHCP changes), else IP — so names follow a device.
 */
object Nicknames {
    fun keyFor(mac: String?, ip: String): String = mac?.takeIf { it.isNotBlank() }?.lowercase() ?: ip

    fun keyFor(device: DeviceResult): String = keyFor(device.mac, device.ipAddress)

    /** The name to show for a device: user nickname if set, else the scan's display name. */
    fun displayName(device: DeviceResult, names: Map<String, String>): String =
        names[keyFor(device)]?.takeIf { it.isNotBlank() } ?: device.displayName

    /** Folds nicknames into snapshots so diffs, history and alerts speak in the user's own names. */
    fun applyNames(snapshots: List<DeviceSnapshot>, names: Map<String, String>): List<DeviceSnapshot> =
        if (names.isEmpty()) snapshots
        else snapshots.map { s -> names[s.key]?.takeIf { it.isNotBlank() }?.let { s.copy(name = it) } ?: s }
}
