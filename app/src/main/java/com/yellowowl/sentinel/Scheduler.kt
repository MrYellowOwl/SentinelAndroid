package com.yellowowl.sentinel

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** How often Sentinel runs an automatic full scan of the current authorized network. */
enum class ScanSchedule(val label: String, val minutes: Long?) {
    OFF("Off", null),
    EVERY_12H("Every 12 hours", 12 * 60),
    DAILY("Daily", 24 * 60),
    WEEKLY("Weekly", 7 * 24 * 60);

    companion object {
        fun parse(value: String?): ScanSchedule = entries.firstOrNull { it.name == value } ?: OFF
    }
}

/** Schedules recurring full scans. Separate from [Monitor], which is continuous change-watching. */
object Scheduler {
    private const val UNIQUE = "sentinel-scheduled-scan"

    fun apply(context: Context, schedule: ScanSchedule) {
        val app = context.applicationContext
        SentinelSettings.setScanSchedule(app, schedule)
        val wm = WorkManager.getInstance(app)
        val minutes = schedule.minutes
        if (minutes == null) {
            wm.cancelUniqueWork(UNIQUE)
            return
        }
        val request = PeriodicWorkRequestBuilder<ScheduledScanWorker>(minutes, TimeUnit.MINUTES).build()
        wm.enqueueUniquePeriodicWork(UNIQUE, ExistingPeriodicWorkPolicy.UPDATE, request)
    }
}

/** Runs one scheduled scan when the phone is back on its authorized network. Reuses the scan engine. */
class ScheduledScanWorker(appContext: Context, params: WorkerParameters) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext
        if (SentinelSettings.scanSchedule(app) == ScanSchedule.OFF) return Result.success()
        val range = NetworkScanner.detectLocalNetwork(app) ?: return Result.success()
        // Only scan a network the user has authorized; otherwise skip quietly until they're back on one.
        if (!SentinelSettings.isAuthorized(app, range.cidr)) return Result.success()
        return try {
            ScanRunner.runNow(app)   // full scan → findings, history, completion notification
            Result.success()
        } catch (_: Exception) {
            Result.retry()
        }
    }
}
