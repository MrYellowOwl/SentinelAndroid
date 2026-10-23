package com.yellowowl.sentinel

import java.net.HttpURLConnection
import java.net.URI
import java.net.URL
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
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
        val cert: CertCheck.CertInfo?
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
            fetched.cert?.let { ci ->
                ci.notAfter?.let { add(WebChecks.certificateFinding(scope, final.host, it, System.currentTimeMillis())) }
                addAll(CertCheck.findings(scope, final.host, ci))
            }
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
            addAll(deepChecks(scope, final))
        }

        WebsiteAuditResult(
            requestedUrl = requested.toString(),
            finalUrl = final.toString(),
            statusCode = fetched.response.statusCode,
            redirectChain = fetched.chain,
            findings = FindingMerge.prioritized(WebChecks.withSummary(scope, host, findings))
        )
    }

    private const val CORS_PROBE_ORIGIN = "https://sentinel-cors-probe.example"

    /** CORS reflection, SRI on the live page, and a bounded sensitive-path sweep. All plain GETs. */
    private suspend fun deepChecks(scope: String, final: URL): List<Finding> = coroutineScope {
        val host = final.host
        val base = "${final.protocol}://${final.authority}"

        val corsAndSri = async {
            val out = ArrayList<Finding>()
            val probe = Http.get(final.toString(), timeoutMillis = 8_000, extraHeaders = mapOf("Origin" to CORS_PROBE_ORIGIN))
            if (probe != null) {
                WebDeep.corsFinding(scope, host, CORS_PROBE_ORIGIN,
                    probe.header("access-control-allow-origin"), probe.header("access-control-allow-credentials"))?.let { out.add(it) }
                if (probe.body.isNotBlank()) WebDeep.sriFinding(scope, host, probe.body)?.let { out.add(it) }
            }
            out
        }

        // Dangerous HTTP methods: read what the server advertises via OPTIONS (we never send a write method).
        val methods = async {
            val opt = Http.get(base, timeoutMillis = 8_000, maxBytes = 1024, followRedirects = false, method = "OPTIONS")
            WebDeep.dangerousMethodsFinding(scope, host, opt?.header("allow"))
        }

        // Soft-404 guard: if the server returns 200 for a known-nonexistent path, its 200s are
        // meaningless and the sweep would be all false positives — so skip it and say why.
        val softProbe = async {
            val randomPath = "/sentinel-not-here-${System.nanoTime().toString(36)}"
            val r = Http.get("$base$randomPath", timeoutMillis = 6_000, maxBytes = 512, followRedirects = false)
            WebDeep.looksLikeSoftNotFound(r?.code)
        }

        // Sensitive-path sweep: probe each path concurrently; report the ones that actually serve.
        val pathProbes = WebDeep.sensitivePaths.map { sp ->
            async {
                val r = Http.get("$base${sp.path}", timeoutMillis = 6_000, maxBytes = 2048, followRedirects = false)
                if (r != null && r.code == 200) WebDeep.exposedPathFinding(scope, host, sp) else null
            }
        }

        val pathFindings = if (softProbe.await()) {
            pathProbes.forEach { it.cancel() }
            listOf(WebDeep.softNotFoundFinding(scope, host))
        } else {
            pathProbes.awaitAll().filterNotNull()
        }

        corsAndSri.await() + listOfNotNull(methods.await()) + pathFindings
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
                val cert = (connection as? HttpsURLConnection)?.let { https ->
                    runCatching {
                        val leaf = https.serverCertificates.filterIsInstance<X509Certificate>().firstOrNull()
                        leaf?.let {
                            val pub = it.publicKey
                            val bits = when (pub) {
                                is java.security.interfaces.RSAPublicKey -> pub.modulus.bitLength()
                                is java.security.interfaces.ECPublicKey -> pub.params.curve.field.fieldSize
                                else -> 0
                            }
                            CertCheck.CertInfo(
                                notAfter = it.notAfter?.time,
                                sigAlg = it.sigAlgName,
                                keyAlgo = pub?.algorithm,
                                keyBits = bits,
                                selfSigned = it.subjectX500Principal == it.issuerX500Principal
                            )
                        }
                    }.getOrNull()
                }
                return FetchResult(HttpResponseInfo(current, code, headers), chain, cert)
            } finally {
                connection.disconnect()
            }
        }
        throw TooManyRedirectsException()
    }
}
