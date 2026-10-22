package com.yellowowl.sentinel

import android.content.Context
import com.google.android.gms.wearable.MessageEvent
import com.google.android.gms.wearable.PutDataMapRequest
import com.google.android.gms.wearable.Wearable
import com.google.android.gms.wearable.WearableListenerService

/** Data Layer paths shared with the Wear OS app (keep in sync with wear/…/WatchPaths.kt). */
object WatchPaths {
    const val STATUS = "/sentinel/status"
    const val START_SCAN = "/sentinel/scan/start"
    const val CANCEL_SCAN = "/sentinel/scan/cancel"
    const val REFRESH = "/sentinel/status/refresh"
}

/** Publishes the current status to a paired Wear OS watch. Silently does nothing without one. */
object WatchSync {
    fun publish(context: Context) {
        val app = context.applicationContext
        val scan = ScanRunner.state.value
        val counts = FindingMerge.countBySeverity(SentinelRepo.findings.value)
        val last = SentinelSettings.lastScan(app)
        try {
            val request = PutDataMapRequest.create(WatchPaths.STATUS).apply {
                dataMap.putInt("high", counts[Severity.HIGH] ?: 0)
                dataMap.putInt("medium", counts[Severity.MEDIUM] ?: 0)
                dataMap.putInt("low", counts[Severity.LOW] ?: 0)
                dataMap.putBoolean("scanning", scan.scanning)
                dataMap.putInt("percent", ((scan.progress?.overall ?: 0f) * 100).toInt())
                dataMap.putString("phase", scan.progress?.phase.orEmpty())
                dataMap.putString("message", scan.message.orEmpty())
                dataMap.putBoolean("isError", scan.isError)
                dataMap.putString("network", last?.cidr.orEmpty())
                dataMap.putLong("lastScanAt", last?.at ?: 0L)
                dataMap.putInt("devices", last?.devices ?: 0)
                // Always changes, so the watch receives an update even if nothing else did.
                dataMap.putLong("updatedAt", System.currentTimeMillis())
            }.asPutDataRequest().setUrgent()
            Wearable.getDataClient(app).putDataItem(request)
        } catch (_: Exception) {
            // No Google Play services / no Wear OS watch: nothing to sync.
        }
    }
}

/** Receives start/cancel/refresh commands from the Wear OS app. */
class WatchCommandService : WearableListenerService() {
    override fun onMessageReceived(messageEvent: MessageEvent) {
        when (messageEvent.path) {
            WatchPaths.START_SCAN -> ScanRunner.request(applicationContext)
            WatchPaths.CANCEL_SCAN -> ScanRunner.cancel(applicationContext)
            WatchPaths.REFRESH -> WatchSync.publish(applicationContext)
        }
    }
}
