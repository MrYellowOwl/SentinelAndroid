package com.yellowowl.sentinel

import android.content.Context
import android.os.Build
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.ForegroundInfo
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.OutOfQuotaPolicy
import androidx.work.WorkManager
import androidx.work.WorkerParameters

/** Runs a network scan as a WorkManager job so it finishes even if the app goes to the background. */
class ScanWorker(appContext: Context, params: WorkerParameters) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        ScanRunner.runNow(applicationContext)
        return Result.success()
    }

    // Only used by WorkManager's compatibility path; we request expedited work on Android 12+ only,
    // where no foreground service is involved.
    override suspend fun getForegroundInfo(): ForegroundInfo =
        ForegroundInfo(Notifier.ID_PROGRESS, Notifier.progressNotification(applicationContext))

    companion object {
        private const val UNIQUE_NAME = "sentinel-network-scan"

        fun enqueue(context: Context) {
            val builder = OneTimeWorkRequestBuilder<ScanWorker>()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                builder.setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
            }
            WorkManager.getInstance(context).enqueueUniqueWork(UNIQUE_NAME, ExistingWorkPolicy.KEEP, builder.build())
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(UNIQUE_NAME)
        }
    }
}
