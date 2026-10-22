package com.yellowowl.sentinel

import org.json.JSONObject

/** UI state for the in-app updater shown in Settings. */
data class AppUpdateStatus(
    val currentVersion: String,
    val checking: Boolean = false,
    val installing: Boolean = false,
    val available: Boolean = false,
    val latestVersion: String? = null,
    val notes: String = "",
    val apkUrl: String? = null,
    val pageUrl: String = "",
    val message: String? = null,
    val isError: Boolean = false
)

/**
 * Pure logic for the in-app updater: where the GitHub repo lives, how to read its
 * "latest release" JSON, and how to decide whether a release is newer than what's installed.
 * The actual download + install lives in [AppInstaller] because it needs Android.
 */
object AppUpdateLogic {
    /** GitHub owner/repo that hosts the app's releases. Keep in sync with the published repo. */
    const val OWNER = "MrYellowOwl"
    const val REPO = "SentinelAndroid"

    fun latestReleaseApiUrl(owner: String = OWNER, repo: String = REPO): String =
        "https://api.github.com/repos/$owner/$repo/releases/latest"

    data class ReleaseInfo(
        val versionName: String,   // normalized, e.g. "1.2.0"
        val notes: String,
        val apkUrl: String?,       // browser_download_url of the .apk asset, if any
        val pageUrl: String        // human release page, used as a fallback
    )

    /** Parses GitHub's "latest release" response. Returns null if it isn't a usable release. */
    fun parse(json: String): ReleaseInfo? {
        return try {
            val o = JSONObject(json)
            if (o.optBoolean("draft", false) || o.optBoolean("prerelease", false)) return null
            val tag = o.optString("tag_name").ifBlank { o.optString("name") }
            if (tag.isBlank()) return null
            val assets = o.optJSONArray("assets")
            var apk: String? = null
            if (assets != null) {
                for (i in 0 until assets.length()) {
                    val a = assets.optJSONObject(i) ?: continue
                    if (a.optString("name").endsWith(".apk", ignoreCase = true)) {
                        apk = a.optString("browser_download_url").ifBlank { null }
                        if (apk != null) break
                    }
                }
            }
            ReleaseInfo(
                versionName = normalize(tag),
                notes = o.optString("body").trim(),
                apkUrl = apk,
                pageUrl = o.optString("html_url")
            )
        } catch (_: Exception) {
            null
        }
    }

    /** Strips a leading "v" and anything after the numeric core, e.g. "v1.2.0-beta" -> "1.2.0". */
    fun normalize(tag: String): String =
        Regex("""\d+(?:\.\d+)*""").find(tag.trim().removePrefix("v").removePrefix("V"))?.value ?: tag.trim()

    /** True when [latest] is a strictly higher dotted version than [current]. */
    fun isNewer(latest: String, current: String): Boolean {
        val a = parts(normalize(latest))
        val b = parts(current)
        val n = maxOf(a.size, b.size)
        for (i in 0 until n) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    private fun parts(v: String): List<Int> =
        v.split('.').map { it.toIntOrNull() ?: 0 }
}
