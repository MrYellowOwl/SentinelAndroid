package com.yellowowl.sentinel

import java.net.HttpURLConnection
import java.net.URI
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Pure throughput math, separated for unit testing. */
object SpeedCalc {
    fun mbps(bytes: Long, millis: Long): Double {
        if (millis <= 0) return 0.0
        return (bytes * 8.0 / 1_000_000.0) / (millis / 1000.0)
    }

    fun format(mbps: Double): String = when {
        mbps >= 100 -> "%.0f Mbps".format(mbps)
        mbps >= 10 -> "%.1f Mbps".format(mbps)
        else -> "%.2f Mbps".format(mbps)
    }
}

data class SpeedResult(val downloadMbps: Double, val latencyMs: Long, val bytes: Long, val millis: Long)

/**
 * Simple internet speed test: a latency probe plus a timed download from Cloudflare's speed endpoint.
 * Measures the phone's internet link; it doesn't upload anything meaningful.
 */
object SpeedTest {
    private const val DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes="
    private const val LATENCY_URL = "https://speed.cloudflare.com/__down?bytes=0"

    suspend fun run(bytes: Long = 25_000_000, onProgress: (Long, Long) -> Unit = { _, _ -> }): Result<SpeedResult> =
        withContext(Dispatchers.IO) {
            try {
                val latency = measureLatency()
                val start = System.currentTimeMillis()
                val conn = (URI("$DOWNLOAD_URL$bytes").toURL().openConnection() as HttpURLConnection).apply {
                    connectTimeout = 10_000; readTimeout = 20_000; requestMethod = "GET"
                    setRequestProperty("User-Agent", "SentinelSecurity/1.0")
                }
                try {
                    if (conn.responseCode != 200) return@withContext Result.failure(IllegalStateException("Speed server returned HTTP ${conn.responseCode}."))
                    var total = 0L
                    val buf = ByteArray(64 * 1024)
                    conn.inputStream.use { input ->
                        while (true) {
                            val read = input.read(buf)
                            if (read <= 0) break
                            total += read
                            onProgress(total, System.currentTimeMillis() - start)
                        }
                    }
                    val millis = System.currentTimeMillis() - start
                    Result.success(SpeedResult(SpeedCalc.mbps(total, millis), latency, total, millis))
                } finally {
                    conn.disconnect()
                }
            } catch (e: Exception) {
                Result.failure(IllegalStateException("Speed test failed: ${e.message ?: e.javaClass.simpleName}"))
            }
        }

    private fun measureLatency(): Long = try {
        val start = System.currentTimeMillis()
        val conn = (URI(LATENCY_URL).toURL().openConnection() as HttpURLConnection).apply {
            connectTimeout = 5_000; readTimeout = 5_000; requestMethod = "GET"
        }
        conn.responseCode
        conn.inputStream.use { it.read() }
        conn.disconnect()
        System.currentTimeMillis() - start
    } catch (_: Exception) {
        -1
    }
}
