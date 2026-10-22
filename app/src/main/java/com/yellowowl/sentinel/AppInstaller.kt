package com.yellowowl.sentinel

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Downloads a release APK and hands it to the system package installer. */
object AppInstaller {
    enum class Result {
        LAUNCHED,          // installer launched
        NEEDS_PERMISSION,  // sent the user to enable "install unknown apps" for this app
        FAILED             // download or install couldn't be completed
    }

    /**
     * Installs the update. On Android 8+ the app itself must be allowed to install packages; if it
     * isn't, we open that settings screen for Sentinel and return [Result.NEEDS_PERMISSION] so the
     * user can grant it and tap again. Only genuine download/IO failures return [Result.FAILED].
     */
    suspend fun downloadAndInstall(context: Context, apkUrl: String): Result = withContext(Dispatchers.IO) {
        // 1) Ensure we're allowed to install APKs (per-app on Android 8+).
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !context.packageManager.canRequestPackageInstalls()) {
            withContext(Dispatchers.Main) {
                runCatching {
                    context.startActivity(
                        Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    )
                }
            }
            return@withContext Result.NEEDS_PERMISSION
        }

        // 2) Download the APK (following GitHub's redirect to its CDN).
        try {
            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            dir.listFiles()?.forEach { it.delete() } // keep only the newest download
            val apk = File(dir, "sentinel-update.apk")

            var url = URL(apkUrl)
            var redirects = 0
            var connection = url.openConnection() as HttpURLConnection
            while (true) {
                connection.connectTimeout = 15000
                connection.readTimeout = 30000
                connection.instanceFollowRedirects = false
                connection.setRequestProperty("User-Agent", "SentinelSecurity-Updater")
                val code = connection.responseCode
                if (code in 300..399 && redirects < 5) {
                    val loc = connection.getHeaderField("Location") ?: break
                    connection.disconnect()
                    url = URL(url, loc)
                    connection = url.openConnection() as HttpURLConnection
                    redirects++
                    continue
                }
                break
            }
            connection.inputStream.use { input -> apk.outputStream().use { input.copyTo(it) } }
            connection.disconnect()
            if (apk.length() <= 0L) return@withContext Result.FAILED

            // 3) Hand it to the system installer.
            val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apk)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            withContext(Dispatchers.Main) { context.startActivity(intent) }
            Result.LAUNCHED
        } catch (_: Exception) {
            Result.FAILED
        }
    }
}
