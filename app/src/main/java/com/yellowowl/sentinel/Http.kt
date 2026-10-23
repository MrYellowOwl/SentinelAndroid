package com.yellowowl.sentinel

import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Minimal HTTP GET with manual redirect following and a capped body. Used by the WordPress audit. */
object Http {
    private const val USER_AGENT = "Mozilla/5.0 (Linux; Android) SentinelSecurity/1.0 (authorized security review)"

    data class Result(
        val code: Int,
        val headers: Map<String, List<String>>,
        val body: String,
        val finalUrl: URL
    ) {
        fun header(name: String): String? = headers[name.lowercase()]?.firstOrNull()
    }

    suspend fun get(
        urlString: String,
        timeoutMillis: Int = 8_000,
        maxBytes: Int = 512 * 1024,
        followRedirects: Boolean = true,
        extraHeaders: Map<String, String> = emptyMap(),
        readTimeoutMillis: Int = timeoutMillis
    ): Result? = withContext(Dispatchers.IO) {
        var current = runCatching { URI(urlString).toURL() }.getOrNull() ?: return@withContext null
        repeat(WebChecks.MAX_REDIRECTS + 1) {
            val connection = runCatching { current.openConnection() as HttpURLConnection }.getOrNull() ?: return@withContext null
            try {
                connection.connectTimeout = timeoutMillis
                connection.readTimeout = readTimeoutMillis
                connection.instanceFollowRedirects = false
                connection.requestMethod = "GET"
                connection.useCaches = false
                connection.setRequestProperty("User-Agent", USER_AGENT)
                connection.setRequestProperty("Accept", "*/*")
                extraHeaders.forEach { (k, v) -> connection.setRequestProperty(k, v) }
                val code = try { connection.responseCode } catch (_: Exception) { return@withContext null }
                if (followRedirects && WebChecks.isRedirect(code)) {
                    val next = WebChecks.resolveRedirect(current, connection.getHeaderField("Location"))
                    if (next != null) { current = next; return@repeat }
                }
                val headers = WebChecks.normalizeHeaders(connection.headerFields)
                val stream = if (code in 200..399) connection.inputStream else connection.errorStream
                val body = stream?.let { readCapped(it, maxBytes) }.orEmpty()
                return@withContext Result(code, headers, body, current)
            } catch (_: Exception) {
                return@withContext null
            } finally {
                connection.disconnect()
            }
        }
        null
    }

    private fun readCapped(stream: java.io.InputStream, maxBytes: Int): String {
        val buffer = java.io.ByteArrayOutputStream()
        val chunk = ByteArray(8192)
        var total = 0
        stream.use {
            while (total < maxBytes) {
                val read = it.read(chunk)
                if (read <= 0) break
                buffer.write(chunk, 0, minOf(read, maxBytes - total))
                total += read
            }
        }
        return buffer.toString("UTF-8")
    }
}
