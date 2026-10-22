package com.yellowowl.sentinel

import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Lightweight, non-destructive website checks: ordinary GET requests, no form submission, no payloads.
 * Redirects are followed manually because Android's HttpURLConnection won't follow HTTP <-> HTTPS redirects.
 */
object WebsiteAuditor {
    // Browser-style prefix so CDNs/bot filters serve the normal page; Sentinel stays identifiable in server logs.
    private const val USER_AGENT = "Mozilla/5.0 (Linux; Android) SentinelSecurity/1.0 (authorized security review)"

    private class FetchResult(
        val response: HttpResponseInfo,
        val chain: List<String>,
        val certNotAfter: Long?
    )

    /** Throws IllegalArgumentException / IllegalStateException with a user-facing message when the audit can't run. */
    suspend fun audit(input: String): WebsiteAuditResult = withContext(Dispatchers.IO) {
        val requested = WebChecks.normalizeUrl(input)
        val scope = WebChecks.scopeFor(requested)
        val host = requested.host

        val fetched = try {
            fetch(requested, timeoutMillis = 10_000)
        } catch (error: Exception) {
            val tls = WebChecks.tlsFailureFinding(scope, host, error)
                ?: throw IllegalStateException(WebChecks.friendlyError(error), error)
            return@withContext WebsiteAuditResult(
                requestedUrl = requested.toString(),
                finalUrl = requested.toString(),
                statusCode = null,
                redirectChain = listOf(requested.toString()),
                findings = listOf(tls)
            )
        }

        val final = fetched.response.url
        // Only probe the other scheme when no custom port was given and we didn't already switch schemes.
        val needsCounterpart = requested.port == -1 && requested.protocol.equals(final.protocol, ignoreCase = true)
        val counterpart = if (needsCounterpart) probeCounterpart(requested) else null

        val findings = buildList {
            addAll(WebChecks.transportFindings(scope, requested, final, counterpart))
            fetched.certNotAfter?.let { add(WebChecks.certificateFinding(scope, final.host, it, System.currentTimeMillis())) }
            // Deep TLS assessment: supported protocol versions + negotiated ciphers, graded.
            if (final.protocol.equals("https", ignoreCase = true)) {
                val report = runCatching {
                    TlsProbe.probe(final.host, if (final.port > 0) final.port else 443)
                }.getOrNull()
                if (report != null) addAll(TlsInspect.findings(scope, final.host, report))
            }
            addAll(WebChecks.analyzeResponse(scope, fetched.response))
            // PHP version → CVE matching (catches version-matchable RCEs like PHP2Shell).
            val phpVersion = WebChecks.phpVersion(fetched.response.headers)
            if (phpVersion != null) {
                val fp = ServiceFingerprint("php", phpVersion)
                addAll(VulnStore.matcher().match(fp).map { it.toFinding(scope, host, if (final.port > 0) final.port else 443, fp) })
                EolData.finding(scope, host, fp, FindingSource.WEB)?.let { add(it) }
            } else if (WebChecks.phpDetectedWithoutVersion(fetched.response.headers)) {
                add(WebChecks.phpHiddenFinding(scope, host))
            }
        }

        WebsiteAuditResult(
            requestedUrl = requested.toString(),
            finalUrl = final.toString(),
            statusCode = fetched.response.statusCode,
            redirectChain = fetched.chain,
            findings = FindingMerge.prioritized(WebChecks.withSummary(scope, host, findings))
        )
    }

    private fun probeCounterpart(requested: URL): CounterpartProbe {
        val otherScheme = if (requested.protocol.equals("https", ignoreCase = true)) "http" else "https"
        return try {
            val result = fetch(URI("$otherScheme://${requested.host}/").toURL(), timeoutMillis = 6_000)
            CounterpartProbe.Reached(result.response.url, result.response.statusCode)
        } catch (_: Exception) {
            CounterpartProbe.Unreachable
        }
    }

    private fun fetch(start: URL, timeoutMillis: Int): FetchResult {
        var current = start
        val chain = mutableListOf(start.toString())
        repeat(WebChecks.MAX_REDIRECTS + 1) {
            val connection = current.openConnection() as HttpURLConnection
            try {
                connection.connectTimeout = timeoutMillis
                connection.readTimeout = timeoutMillis
                connection.instanceFollowRedirects = false
                connection.useCaches = false
                connection.requestMethod = "GET"
                connection.setRequestProperty("User-Agent", USER_AGENT)
                connection.setRequestProperty("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")

                val code = connection.responseCode
                if (WebChecks.isRedirect(code)) {
                    val next = WebChecks.resolveRedirect(current, connection.getHeaderField("Location"))
                    if (next != null) {
                        current = next
                        chain += next.toString()
                        return@repeat
                    }
                }
                val headers = WebChecks.normalizeHeaders(connection.headerFields)
                val certNotAfter = (connection as? HttpsURLConnection)?.let { https ->
                    runCatching {
                        https.serverCertificates.filterIsInstance<X509Certificate>().firstOrNull()?.notAfter?.time
                    }.getOrNull()
                }
                return FetchResult(HttpResponseInfo(current, code, headers), chain, certNotAfter)
            } finally {
                connection.disconnect()
            }
        }
        throw TooManyRedirectsException()
    }
}
