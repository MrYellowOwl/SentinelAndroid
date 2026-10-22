package com.yellowowl.sentinel

import android.content.Context
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

/** Controls scheduled network monitoring: a periodic background scan that alerts on changes. */
object Monitor {
    private const val UNIQUE = "sentinel-network-monitor"
    const val INTERVAL_MINUTES = 30L

    fun enable(context: Context, cidr: String, initialBaseline: List<DeviceSnapshot>?) {
        val app = context.applicationContext
        MonitorStore.setEnabled(app, true, cidr)
        if (initialBaseline != null) MonitorStore.saveBaseline(app, cidr, initialBaseline)
        val request = PeriodicWorkRequestBuilder<MonitorWorker>(INTERVAL_MINUTES, TimeUnit.MINUTES).build()
        WorkManager.getInstance(app).enqueueUniquePeriodicWork(UNIQUE, ExistingPeriodicWorkPolicy.UPDATE, request)
    }

    fun disable(context: Context) {
        val app = context.applicationContext
        MonitorStore.setEnabled(app, false, null)
        WorkManager.getInstance(app).cancelUniqueWork(UNIQUE)
    }
}

/** Runs one monitoring pass: scan the watched network, diff against the baseline, alert on changes. */
class MonitorWorker(appContext: Context, params: WorkerParameters) : CoroutineWorker(appContext, params) {
    override suspend fun doWork(): Result {
        val app = applicationContext
        val cidr = MonitorStore.monitoredCidr(app) ?: return Result.success()
        if (!MonitorStore.isEnabled(app)) return Result.success()
        val range = NetworkScanner.detectLocalNetwork(app) ?: return Result.success()
        // Only scan when we're back on the watched, authorized network.
        if (range.cidr != cidr || !SentinelSettings.isAuthorized(app, cidr)) return Result.success()

        return try {
            val result = NetworkScanner.scanLocalNetwork(range, app, SentinelSettings.scanProfile(app)) { }
            val run = NetworkFindings.from(result) + result.devices.flatMap { VulnStore.matcher().findingsFor(result.cidr, it) }
            SentinelRepo.replaceRun(FindingSource.NETWORK, result.cidr, run)
            SentinelSettings.saveLastScan(app, SentinelSettings.LastScan(result.cidr, System.currentTimeMillis(), result.devices.size))

            val snapshot = Nicknames.applyNames(ScanDiffer.snapshot(result.devices), NicknameStore.current(app))
            val baseline = MonitorStore.loadBaseline(app, cidr)
            if (baseline != null) {
                val diff = ScanDiffer.diff(baseline, snapshot)
                if (!diff.isEmpty) Notifier.networkChange(app, diff)
            }
            MonitorStore.saveBaseline(app, cidr, snapshot)
            Result.success()
        } catch (_: Exception) {
            Result.retry()
        }
    }
}
