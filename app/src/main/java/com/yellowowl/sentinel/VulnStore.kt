package com.yellowowl.sentinel

import android.content.Context
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class VulnDbStatus(
    val count: Int = 0,
    val updated: String = "never",
    val source: String = "none",
    val updating: Boolean = false,
    val message: String? = null,
    val isError: Boolean = false
)

/** App-wide holder for the loaded vulnerability database and its matcher. */
object VulnStore {
    private val _status = MutableStateFlow(VulnDbStatus())
    val status: StateFlow<VulnDbStatus> = _status.asStateFlow()

    @Volatile private var matcher: VulnMatcher = VulnMatcher(emptyList())
    @Volatile private var appContext: Context? = null
    private val initialLoad = CountDownLatch(1)

    fun init(context: Context) {
        if (appContext != null) return
        synchronized(this) {
            if (appContext != null) return
            appContext = context.applicationContext
        }
        _status.value = _status.value.copy(source = "loading")
        // Parse off the main thread — the baked seed can hold thousands of entries, and this runs
        // in Application.onCreate(). A daemon thread keeps cold-start snappy.
        Thread {
            try {
                apply(VulnFeed.loadCachedOrSeed(appContext!!))
            } finally {
                initialLoad.countDown()
            }
        }.apply { isDaemon = true; name = "vulnstore-load" }.start()
    }

    /**
     * The matcher, used only from background scan threads. Waits briefly for the initial DB load so a
     * scan launched moments after startup still matches against the full database rather than an empty one.
     */
    fun matcher(): VulnMatcher {
        runCatching { initialLoad.await(10, TimeUnit.SECONDS) }
        return matcher
    }

    private fun apply(feed: VulnFeedData?) {
        if (feed == null) return
        matcher = VulnMatcher(feed.vulns)
        _status.value = _status.value.copy(count = feed.count, updated = feed.updated, source = feed.source)
    }

    /** Downloads the latest feed. Returns true on success. */
    suspend fun update(context: Context): Boolean {
        val url = SentinelSettings.feedUrl(context)
        _status.value = _status.value.copy(updating = true, message = null, isError = false)
        return try {
            val feed = VulnFeed.update(context, url)
            apply(feed)
            _status.value = _status.value.copy(updating = false, message = "Updated · ${feed.count} entries.", isError = false)
            true
        } catch (e: Exception) {
            _status.value = _status.value.copy(updating = false, message = e.message ?: "Update failed.", isError = true)
            false
        }
    }
}
