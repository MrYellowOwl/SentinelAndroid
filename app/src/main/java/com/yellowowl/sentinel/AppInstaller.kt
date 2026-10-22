package com.yellowowl.sentinel

import android.content.Context
import android.content.Intent
import android.net.Uri
import androidx.core.content.FileProvider
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Downloads a release APK and hands it to the system package installer. */
object AppInstaller {
    /**
     * Downloads [apkUrl] into cache and launches the installer. Returns true if the install
     * intent was launched. On any failure the caller should fall back to opening the release page.
     */
    suspend fun downloadAndInstall(context: Context, apkUrl: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val dir = File(context.cacheDir, "updates").apply { mkdirs() }
            // Clear stale downloads so we never install an old cached APK.
            dir.listFiles()?.forEach { it.delete() }
            val apk = File(dir, "sentinel-update.apk")

            var url = URL(apkUrl)
            var redirects = 0
            var connection = url.openConnection() as HttpURLConnection
            // GitHub asset URLs redirect to a CDN; follow a few hops manually (incl. https<->http).
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
            if (apk.length() <= 0L) return@withContext false

            val uri: Uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", apk)
            val intent = Intent(Intent.ACTION_VIEW).apply {
                setDataAndType(uri, "application/vnd.android.package-archive")
                addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            withContext(Dispatchers.Main) { context.startActivity(intent) }
            true
        } catch (_: Exception) {
            false
        }
    }
}
