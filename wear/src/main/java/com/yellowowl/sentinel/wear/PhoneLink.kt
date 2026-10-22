package com.yellowowl.sentinel.wear

import android.content.Context
import com.google.android.gms.wearable.CapabilityClient
import com.google.android.gms.wearable.DataMap
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.Wearable
import kotlinx.coroutines.tasks.await

/** Data Layer paths shared with the phone app (keep in sync with app/…/WatchSync.kt). */
object WatchPaths {
    const val STATUS = "/sentinel/status"
    const val START_SCAN = "/sentinel/scan/start"
    const val CANCEL_SCAN = "/sentinel/scan/cancel"
    const val REFRESH = "/sentinel/status/refresh"
    /** Declared by the phone app in res/values/wear.xml. */
    const val PHONE_CAPABILITY = "sentinel_phone"
}

/** Latest status published by the phone. */
data class PhoneStatus(
    val high: Int,
    val medium: Int,
    val low: Int,
    val scanning: Boolean,
    val percent: Int,
    val phase: String,
    val message: String,
    val isError: Boolean,
    val network: String,
    val lastScanAt: Long,
    val devices: Int
) {
    companion object {
        fun from(map: DataMap) = PhoneStatus(
            high = map.getInt("high", 0),
            medium = map.getInt("medium", 0),
            low = map.getInt("low", 0),
            scanning = map.getBoolean("scanning", false),
            percent = map.getInt("percent", 0),
            phase = map.getString("phase", ""),
            message = map.getString("message", ""),
            isError = map.getBoolean("isError", false),
            network = map.getString("network", ""),
            lastScanAt = map.getLong("lastScanAt", 0L),
            devices = map.getInt("devices", 0)
        )
    }
}

object PhoneLink {
    /** Reads the last status the phone published (cached on the watch even if the phone is out of range). */
    suspend fun loadStatus(context: Context): PhoneStatus? = try {
        val buffer = Wearable.getDataClient(context).dataItems.await()
        try {
            buffer.firstOrNull { it.uri.path == WatchPaths.STATUS }
                ?.let { PhoneStatus.from(DataMapItem.fromDataItem(it).dataMap) }
        } finally {
            buffer.release()
        }
    } catch (_: Exception) {
        null
    }

    /** Sends [path] to every reachable phone running Sentinel. Returns false if none was reachable. */
    suspend fun send(context: Context, path: String): Boolean = try {
        val nodes = Wearable.getCapabilityClient(context)
            .getCapability(WatchPaths.PHONE_CAPABILITY, CapabilityClient.FILTER_REACHABLE)
            .await()
            .nodes
        val messages = Wearable.getMessageClient(context)
        nodes.forEach { node -> messages.sendMessage(node.id, path, ByteArray(0)).await() }
        nodes.isNotEmpty()
    } catch (_: Exception) {
        false
    }
}
