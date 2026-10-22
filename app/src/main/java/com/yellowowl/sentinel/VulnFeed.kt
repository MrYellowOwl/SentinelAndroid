package com.yellowowl.sentinel

import android.content.Context
import java.io.File
import java.net.HttpURLConnection
import java.net.URI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** The parsed vulnerability feed: metadata plus the entries the matcher uses. */
data class VulnFeedData(
    val formatVersion: Int,
    val updated: String,
    val vulns: List<KnownVuln>,
    val source: String // "bundled seed", "cache", or the feed URL
) {
    val count: Int get() = vulns.size
}

/**
 * Loads, caches and refreshes the vulnerability feed. The feed is plain CVE metadata (id, product,
 * affected range, CVSS, summary, an exploit-exists flag and a reference link) — never exploit code.
 * Published to a GitHub raw URL; see tools/build_feed.py for how to generate it.
 */
object VulnFeed {
    const val DEFAULT_FEED_URL =
        "https://raw.githubusercontent.com/MrYellowOwl/SentinelAndroid/main/feed/vuln_feed.json"
    private const val CACHE_FILE = "vuln_feed.json"
    private const val MAX_BYTES = 12 * 1024 * 1024

    fun cacheFile(context: Context): File = File(context.filesDir, CACHE_FILE)

    /** Cached feed if present and valid, otherwise the bundled seed, otherwise null. */
    fun loadCachedOrSeed(context: Context): VulnFeedData? {
        val cache = cacheFile(context)
        if (cache.isFile) {
            runCatching { parse(cache.readText(), source = "cache") }.getOrNull()?.let { return it }
        }
        return loadSeed(context)
    }

    private fun loadSeed(context: Context): VulnFeedData? = runCatching {
        context.resources.openRawResource(R.raw.vuln_seed).use { stream ->
            parse(stream.readBytes().toString(Charsets.UTF_8), source = "bundled seed")
        }
    }.getOrNull()

    /** Downloads the feed, validates and caches it. Throws with a user-facing message on failure. */
    suspend fun update(context: Context, url: String): VulnFeedData = withContext(Dispatchers.IO) {
        val target = URI(url).toURL()
        require(target.protocol.equals("https", true)) { "The feed URL must use HTTPS." }
        val connection = (target.openConnection() as HttpURLConnection).apply {
            connectTimeout = 15_000
            readTimeout = 20_000
            requestMethod = "GET"
            setRequestProperty("Accept", "application/json")
            setRequestProperty("User-Agent", "SentinelSecurity/1.0")
        }
        try {
            val code = connection.responseCode
            if (code != 200) throw IllegalStateException("The feed server returned HTTP $code.")
            val length = connection.contentLength
            if (length > MAX_BYTES) throw IllegalStateException("The feed is unexpectedly large; refusing to download.")
            val body = connection.inputStream.readBytes()
            if (body.size > MAX_BYTES) throw IllegalStateException("The feed is unexpectedly large; refusing to download.")
            val text = body.toString(Charsets.UTF_8)
            val parsed = parse(text, source = url) ?: throw IllegalStateException("The feed wasn't in the expected format.")
            cacheFile(context).writeText(text, Charsets.UTF_8)
            parsed
        } catch (e: IllegalStateException) {
            throw e
        } catch (e: Exception) {
            throw IllegalStateException("Couldn't update the database: ${e.message ?: e.javaClass.simpleName}", e)
        } finally {
            connection.disconnect()
        }
    }

    /** Parses the feed JSON. Returns null if the shape is wrong. Unknown entries are skipped, not fatal. */
    fun parse(json: String, source: String): VulnFeedData? {
        val root = runCatching { JSONObject(json) }.getOrNull() ?: return null
        val array = root.optJSONArray("vulns") ?: return null
        val vulns = ArrayList<KnownVuln>(array.length())
        for (i in 0 until array.length()) {
            val item = array.optJSONObject(i) ?: continue
            val id = item.optString("id")
            val product = item.optString("product")
            if (id.isBlank() || product.isBlank()) continue
            val exact = item.optJSONArray("exact")?.let { arr ->
                (0 until arr.length()).mapNotNull { arr.optString(it).ifBlank { null } }
            }.orEmpty()
            vulns.add(
                KnownVuln(
                    id = id,
                    product = product,
                    range = VersionRange(
                        introduced = item.optString("introduced").ifBlank { null },
                        fixed = item.optString("fixed").ifBlank { null },
                        exact = exact
                    ),
                    cvss = if (item.has("cvss")) item.optDouble("cvss").takeIf { !it.isNaN() } else null,
                    summary = item.optString("summary"),
                    exploitAvailable = item.optBoolean("exploit", false),
                    referenceUrl = item.optString("url").ifBlank { null },
                    fixText = item.optString("fix").ifBlank { null }
                )
            )
        }
        return VulnFeedData(
            formatVersion = root.optInt("version", 1),
            updated = root.optString("updated").ifBlank { "unknown" },
            vulns = vulns,
            source = source
        )
    }
}
