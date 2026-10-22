package com.yellowowl.sentinel

import android.Manifest
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat

/**
 * Phone notifications. Galaxy watches (including Tizen models like the Active 2) and Wear OS watches
 * mirror these automatically, so this is also how alerts reach any paired watch.
 */
object Notifier {
    private const val CHANNEL_RESULTS = "scan_results"
    private const val CHANNEL_ALERTS = "security_alerts"
    private const val CHANNEL_PROGRESS = "scan_progress"

    private const val ID_NETWORK = 1001
    private const val ID_WEB = 1002
    const val ID_PROGRESS = 1003
    private const val ID_MONITOR = 1004

    fun createChannels(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannels(
            listOf(
                NotificationChannel(CHANNEL_ALERTS, "High-severity alerts", NotificationManager.IMPORTANCE_HIGH).apply {
                    description = "A scan found high-severity issues."
                },
                NotificationChannel(CHANNEL_RESULTS, "Scan results", NotificationManager.IMPORTANCE_DEFAULT).apply {
                    description = "A network scan or website audit finished."
                },
                NotificationChannel(CHANNEL_PROGRESS, "Scan in progress", NotificationManager.IMPORTANCE_LOW).apply {
                    description = "Shown on older Android versions while a scan runs in the background."
                }
            )
        )
    }

    /** True when alerts are switched on in the app and allowed by the system. */
    fun canNotify(context: Context): Boolean {
        if (!SentinelSettings.alertsEnabled(context)) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return false
        return NotificationManagerCompat.from(context).areNotificationsEnabled()
    }

    fun networkScanComplete(context: Context, result: NetworkScanResult, run: List<Finding>) {
        val high = run.count { it.severity == Severity.HIGH }
        val title = if (high > 0) "$high high-severity issue(s) on your network" else "Network scan complete"
        val text = "${result.devices.size} device(s) on ${result.cidr} · ${summary(run)}"
        post(context, ID_NETWORK, if (high > 0) CHANNEL_ALERTS else CHANNEL_RESULTS, title, text, scanAgain = true)
    }

    /** Website audits notify only for High findings; otherwise the user is already looking at the result. */
    fun websiteAuditComplete(context: Context, host: String, findings: List<Finding>) {
        val high = findings.count { it.severity == Severity.HIGH }
        if (high == 0) return
        post(context, ID_WEB, CHANNEL_ALERTS, "$high high-severity issue(s) on $host", summary(findings), scanAgain = false)
    }

    /** Alerts on network changes found by background monitoring (new devices, new ports). */
    fun networkChange(context: Context, diff: ScanDiff) {
        val lines = ScanDiffer.summaryLines(diff)
        if (lines.isEmpty()) return
        val hasNew = diff.newDevices.isNotEmpty()
        val title = when {
            hasNew && diff.newDevices.size == 1 -> "New device on your network"
            hasNew -> "${diff.newDevices.size} new devices on your network"
            else -> "${diff.changeCount} network change(s)"
        }
        post(context, ID_MONITOR, CHANNEL_ALERTS, title, lines.joinToString("\n"), scanAgain = false)
    }

    fun progressNotification(context: Context): Notification =
        NotificationCompat.Builder(context, CHANNEL_PROGRESS)
            .setSmallIcon(R.drawable.ic_stat_sentinel)
            .setContentTitle("Scanning your network…")
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setProgress(0, 0, true)
            .build()

    private fun post(context: Context, id: Int, channel: String, title: String, text: String, scanAgain: Boolean) {
        if (!SentinelSettings.alertsEnabled(context)) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) return

        val builder = NotificationCompat.Builder(context, channel)
            .setSmallIcon(R.drawable.ic_stat_sentinel)
            .setColor(0xFF45E0B4.toInt())
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setContentIntent(openAppIntent(context))
            .setAutoCancel(true)
            .setCategory(NotificationCompat.CATEGORY_STATUS)
            .setPriority(if (channel == CHANNEL_ALERTS) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
        if (scanAgain) builder.addAction(0, "Scan again", scanAgainIntent(context))

        try {
            NotificationManagerCompat.from(context).notify(id, builder.build())
        } catch (_: SecurityException) {
            // Permission revoked between the check and the call; nothing to do.
        }
    }

    private fun summary(findings: List<Finding>): String {
        val counts = FindingMerge.countBySeverity(findings)
        val parts = listOf(Severity.HIGH, Severity.MEDIUM, Severity.LOW)
            .mapNotNull { severity -> counts[severity]?.takeIf { it > 0 }?.let { "$it ${severity.label}" } }
        return if (parts.isEmpty()) "No issues found" else parts.joinToString(", ")
    }

    private fun openAppIntent(context: Context): PendingIntent {
        val intent = Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP)
        return PendingIntent.getActivity(context, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }

    private fun scanAgainIntent(context: Context): PendingIntent {
        val intent = Intent(context, ScanActionReceiver::class.java).setAction(ScanActionReceiver.ACTION_SCAN)
        return PendingIntent.getBroadcast(context, 1, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }
}
