package com.yellowowl.sentinel

import java.net.ConnectException
import java.net.SocketTimeoutException
import java.net.URI
import java.net.URL
import java.net.UnknownHostException
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateExpiredException
import java.security.cert.CertificateNotYetValidException
import javax.net.ssl.SSLException
import javax.net.ssl.SSLPeerUnverifiedException

/** One HTTP response. Header names are lower-case. */
data class HttpResponseInfo(
    val url: URL,
    val statusCode: Int,
    val headers: Map<String, List<String>>
) {
    fun header(name: String): String? = headers[name.lowercase()]?.firstOrNull()
    fun headerValues(name: String): List<String> = headers[name.lowercase()].orEmpty()
}

/** Outcome of trying the other scheme (http:// when https:// was audited, and vice versa). */
sealed class CounterpartProbe {
    data class Reached(val finalUrl: URL, val statusCode: Int) : CounterpartProbe()
    object Unreachable : CounterpartProbe()
}

class TooManyRedirectsException : Exception("The website redirected too many times.")

/** Pure analysis for the website audit. Network I/O lives in [WebsiteAuditor]. */
object WebChecks {
    const val MAX_REDIRECTS = 8
    private const val SIX_MONTHS_SECONDS = 15_552_000L
    private const val DAY_MILLIS = 24L * 60 * 60 * 1000

    fun normalizeUrl(input: String): URL {
        val value = input.trim()
        require(value.isNotEmpty()) { "Enter a website address." }
        require(value.none { it.isWhitespace() }) { "Website addresses can't contain spaces." }
        val candidate = if (value.contains("://")) value else "https://$value"
        val uri = try {
            URI(candidate)
        } catch (_: Exception) {
            throw IllegalArgumentException("That doesn't look like a valid website address.")
        }
        val scheme = uri.scheme?.lowercase()
        require(scheme == "http" || scheme == "https") { "Only http:// and https:// addresses are supported." }
        require(uri.rawUserInfo == null) { "Addresses containing a username or password aren't supported." }
        require(!uri.host.isNullOrBlank()) { "That doesn't look like a valid website address." }
        return uri.toURL()
    }

    fun scopeFor(url: URL): String = url.host.lowercase()

    fun isRedirect(statusCode: Int): Boolean = statusCode in 300..399 && statusCode != 304

    @Suppress("DEPRECATION")
    fun resolveRedirect(base: URL, location: String?): URL? {
        if (location.isNullOrBlank()) return null
        return try {
            val next = URL(base, location.trim())
            if (next.protocol.equals("http", true) || next.protocol.equals("https", true)) next else null
        } catch (_: Exception) {
            null
        }
    }

    /** Merges header maps from HttpURLConnection (which can contain a null key and mixed-case names). */
    fun normalizeHeaders(raw: Map<String?, List<String>?>): Map<String, List<String>> {
        val merged = linkedMapOf<String, MutableList<String>>()
        raw.forEach { (name, values) ->
            if (name != null) merged.getOrPut(name.lowercase()) { mutableListOf() }.addAll(values.orEmpty())
        }
        return merged
    }

    fun analyzeResponse(scope: String, response: HttpResponseInfo): List<Finding> {
        val findings = mutableListOf<Finding>()
        val host = response.url.host
        val isHttps = response.url.protocol.equals("https", true)
        fun add(title: String, severity: Severity, details: String, remediation: String) {
            findings += Finding(
                title = title, severity = severity, source = FindingSource.WEB, scope = scope,
                target = host, details = details, remediation = remediation
            )
        }

        val code = response.statusCode
        if (code >= 500) {
            add(
                "Website returned a server error ($code)", Severity.LOW,
                "The page answered with HTTP $code. This may be temporary and isn't a security issue by itself, but the header results below may not reflect the normal page.",
                "Check the server or application logs, then run the audit again once the site is healthy."
            )
        } else if (code >= 400) {
            add(
                "Page returned HTTP $code", Severity.INFO,
                "The server answered with HTTP $code (for example, blocked or not found). Header results may differ from what normal visitors get.",
                "Audit a public page that loads normally, such as the home page."
            )
        }

        if (isHttps) {
            val hsts = response.header("strict-transport-security")
            if (hsts == null) {
                add(
                    "HSTS not enabled", Severity.MEDIUM,
                    "The response has no Strict-Transport-Security header, so a browser can still be tricked into loading the site over plain HTTP.",
                    "Add \"Strict-Transport-Security: max-age=31536000\" once you've confirmed the whole site works over HTTPS."
                )
            } else {
                val maxAge = Regex("max-age\\s*=\\s*\"?(\\d+)", RegexOption.IGNORE_CASE).find(hsts)
                    ?.groupValues?.get(1)?.toLongOrNull()
                if (maxAge == null || maxAge < SIX_MONTHS_SECONDS) {
                    add(
                        "HSTS max-age is short", Severity.LOW,
                        "HSTS is set, but max-age is ${maxAge ?: "missing"} seconds. Under 6 months gives limited protection.",
                        "Raise max-age to at least 15552000 (6 months); 31536000 (1 year) is common."
                    )
                }
            }
        }

        val csp = response.header("content-security-policy")
        if (csp == null) {
            add(
                "Content Security Policy not set", Severity.MEDIUM,
                "There's no Content-Security-Policy header. A CSP limits the damage if an attacker manages to inject a script into a page.",
                "Define a Content-Security-Policy listing the script, style, image, frame and connection sources the site actually uses. Start in report-only mode to test it."
            )
        }

        val nosniff = response.header("x-content-type-options")
        if (nosniff == null || !nosniff.trim().equals("nosniff", ignoreCase = true)) {
            add(
                "X-Content-Type-Options not set", Severity.LOW,
                "Without \"X-Content-Type-Options: nosniff\", browsers may guess file types, which can turn an uploaded file into a script.",
                "Send \"X-Content-Type-Options: nosniff\" on all responses."
            )
        }

        if (response.header("x-frame-options") == null && csp?.contains("frame-ancestors", ignoreCase = true) != true) {
            add(
                "Clickjacking protection not set", Severity.LOW,
                "Neither X-Frame-Options nor a CSP frame-ancestors rule is present, so other sites can embed this page in a frame.",
                "Send \"X-Frame-Options: SAMEORIGIN\" or a CSP \"frame-ancestors 'self'\" rule unless the page must be embeddable."
            )
        }

        if (response.header("referrer-policy") == null) {
            add(
                "Referrer-Policy not set", Severity.INFO,
                "Modern browsers default to a reasonable policy, but setting one explicitly avoids leaking full URLs to other sites.",
                "Send \"Referrer-Policy: strict-origin-when-cross-origin\" (or stricter)."
            )
        }

        response.header("x-powered-by")?.let { value ->
            add(
                "Technology disclosed in X-Powered-By", Severity.INFO,
                "The server announces \"${value.take(80)}\". This helps attackers pick exploits for that platform.",
                "Remove the X-Powered-By header (e.g. expose_php = Off for PHP)."
            )
        }

        response.header("server")?.let { value ->
            if (value.any { it.isDigit() }) {
                add(
                    "Server version disclosed", Severity.INFO,
                    "The Server header reveals \"${value.take(80)}\", including a version number.",
                    "Hide the version (e.g. ServerTokens Prod for Apache, server_tokens off for nginx)."
                )
            }
        }

        val cookies = response.headerValues("set-cookie").map(::parseCookie)
        if (isHttps) {
            val insecure = cookies.filter { !it.secure }
            if (insecure.isNotEmpty()) {
                add(
                    "Cookies set without the Secure flag", Severity.LOW,
                    "${insecure.size} cookie(s) can also be sent over plain HTTP: ${namesOf(insecure)}.",
                    "Add the Secure attribute to every cookie set by an HTTPS site."
                )
            }
        }
        val scriptReadable = cookies.filter { !it.httpOnly }
        if (scriptReadable.isNotEmpty()) {
            add(
                "Cookies readable by JavaScript", Severity.INFO,
                "${scriptReadable.size} cookie(s) lack HttpOnly: ${namesOf(scriptReadable)}. That's fine for preference or analytics cookies, but session cookies should be HttpOnly.",
                "Add HttpOnly to session and authentication cookies."
            )
        }
        val noSameSite = cookies.filter { it.sameSite == null || it.sameSite == "none" }
        if (noSameSite.isNotEmpty()) {
            add(
                "Cookies without SameSite protection", Severity.LOW,
                "${noSameSite.size} cookie(s) have no SameSite attribute (or SameSite=None): ${namesOf(noSameSite)}. Cross-site requests will send them, enabling CSRF against session cookies.",
                "Set SameSite=Lax (or Strict) on session cookies; use SameSite=None only with Secure for genuinely cross-site cookies."
            )
        }

        return findings
    }

    fun transportFindings(
        scope: String,
        requested: URL,
        final: URL,
        counterpart: CounterpartProbe?
    ): List<Finding> {
        val host = requested.host
        fun finding(title: String, severity: Severity, details: String, remediation: String) = Finding(
            title = title, severity = severity, source = FindingSource.WEB, scope = scope,
            target = host, details = details, remediation = remediation
        )
        val requestedHttps = requested.protocol.equals("https", true)
        val finalHttps = final.protocol.equals("https", true)
        val redirectOk = finding(
            "HTTP redirects to HTTPS", Severity.INFO,
            "Visitors who type the plain http:// address are sent to the secure version.",
            "Keep the redirect in place and enable HSTS so browsers skip the insecure first request."
        )

        return when {
            !requestedHttps && finalHttps -> listOf(redirectOk)
            requestedHttps && !finalHttps -> listOf(
                finding(
                    "HTTPS redirects to an insecure page", Severity.HIGH,
                    "The https:// address redirected to $final, so visitors end up on an unencrypted connection.",
                    "Fix the redirect so every page stays on HTTPS."
                )
            )
            requestedHttps -> when (counterpart) {
                is CounterpartProbe.Reached -> when {
                    counterpart.finalUrl.protocol.equals("https", true) -> listOf(redirectOk)
                    counterpart.statusCode < 400 -> listOf(
                        finding(
                            "Plain HTTP version doesn't redirect", Severity.MEDIUM,
                            "http://$host loads without redirecting to HTTPS (HTTP ${counterpart.statusCode}), so some visitors use an unencrypted connection.",
                            "Redirect all http:// requests to https:// with a 301, then enable HSTS."
                        )
                    )
                    else -> emptyList()
                }
                CounterpartProbe.Unreachable -> listOf(
                    finding(
                        "Plain HTTP isn't offered", Severity.INFO,
                        "Nothing answered on http://$host, so the site is only reachable over HTTPS.",
                        "No action needed. Optionally add a port-80 redirect so typed addresses still work."
                    )
                )
                null -> emptyList()
            }
            else -> when (counterpart) {
                is CounterpartProbe.Reached -> listOf(
                    finding(
                        "HTTPS available but not enforced", Severity.MEDIUM,
                        "https://$host works, but the http:// address stays on plain HTTP instead of redirecting.",
                        "Redirect all http:// requests to https:// with a 301, then enable HSTS."
                    )
                )
                else -> listOf(
                    finding(
                        "Website doesn't use HTTPS", Severity.HIGH,
                        "The page loaded over plain HTTP and no working HTTPS version was found, so traffic can be read or changed in transit.",
                        "Install a TLS certificate (free from Let's Encrypt) and redirect all traffic to HTTPS."
                    )
                )
            }
        }
    }

    fun certificateFinding(scope: String, host: String, notAfterMillis: Long, nowMillis: Long): Finding {
        val daysRemaining = Math.floorDiv(notAfterMillis - nowMillis, DAY_MILLIS)
        val (title, severity, details) = when {
            daysRemaining < 0 -> Triple("TLS certificate has expired", Severity.HIGH, "The certificate's expiry date has passed.")
            daysRemaining <= 14 -> Triple("TLS certificate expires in $daysRemaining day(s)", Severity.HIGH, "Visitors will see security warnings once it expires.")
            daysRemaining <= 30 -> Triple("TLS certificate expires in $daysRemaining days", Severity.MEDIUM, "Renewal should normally have happened by now.")
            else -> Triple("TLS certificate is valid", Severity.INFO, "The certificate passed validation and has $daysRemaining days left.")
        }
        return Finding(
            title = title, severity = severity, source = FindingSource.WEB, scope = scope, target = host,
            details = details,
            remediation = if (severity == Severity.INFO) "Keep automatic renewal (e.g. certbot) running."
            else "Renew the certificate now and check that automatic renewal (e.g. certbot timer) is working."
        )
    }

    /** Returns a finding for TLS/certificate failures, or null if [error] isn't TLS-related. */
    fun tlsFailureFinding(scope: String, host: String, error: Throwable): Finding? {
        val chain = generateSequence(error) { it.cause }.take(12).toList()
        if (chain.none { it is SSLException }) return null
        val text = chain.joinToString(" ") { it.message.orEmpty() }
        val (title, details, fix) = when {
            chain.any { it is CertificateExpiredException } || text.contains("expired", ignoreCase = true) -> Triple(
                "TLS certificate has expired",
                "The secure connection was refused because the certificate is past its expiry date. Browsers show a full-page warning.",
                "Renew the certificate now and check that automatic renewal is working."
            )
            chain.any { it is CertificateNotYetValidException } -> Triple(
                "TLS certificate isn't valid yet",
                "The certificate's start date is in the future (or the server or phone clock is wrong).",
                "Check the server clock and reissue the certificate if needed."
            )
            chain.any { it is SSLPeerUnverifiedException } || text.contains("not verified", ignoreCase = true) -> Triple(
                "Certificate doesn't match the website name",
                "The certificate was issued for a different hostname than $host.",
                "Issue a certificate that covers $host (and www. if used)."
            )
            chain.any { it is CertPathValidatorException } || text.contains("trust anchor", ignoreCase = true) -> Triple(
                "TLS certificate isn't trusted",
                "The certificate is self-signed, from an unknown authority, or the server isn't sending the intermediate certificate.",
                "Use a certificate from a public CA and serve the full chain (fullchain.pem with certbot)."
            )
            else -> Triple(
                "Secure connection (TLS) failed",
                "The TLS handshake failed: ${error.message.orEmpty().take(160)}",
                "Check the server's TLS configuration; enable TLS 1.2 and 1.3 with modern ciphers."
            )
        }
        return Finding(
            title = title, severity = Severity.HIGH, source = FindingSource.WEB, scope = scope,
            target = host, details = details, remediation = fix
        )
    }

    fun friendlyError(error: Throwable): String = when (error) {
        is UnknownHostException -> "Couldn't find that website. Check the spelling and your internet connection."
        is SocketTimeoutException -> "The website took too long to respond. Try again later."
        is ConnectException -> "Couldn't connect to the website. It may be down or blocking connections."
        is TooManyRedirectsException -> error.message!!
        is IllegalArgumentException -> error.message ?: "That doesn't look like a valid website address."
        is IllegalStateException -> error.message ?: "The audit couldn't complete."
        else -> "The audit couldn't complete: ${error.message ?: error.javaClass.simpleName}"
    }

    /** Adds a summary line when nothing above Info was found. */
    fun withSummary(scope: String, host: String, findings: List<Finding>): List<Finding> {
        if (findings.any { it.severity.rank > Severity.INFO.rank }) return findings
        return findings + Finding(
            title = "Baseline checks passed", severity = Severity.INFO, source = FindingSource.WEB, scope = scope,
            target = host,
            details = "No transport or header issues were found by these checks. This isn't a full penetration test.",
            remediation = "Keep software updated and consider an authenticated application review."
        )
    }

    /** Extracts a PHP x.y.z version from X-Powered-By or Server headers, or null. */
    fun phpVersion(headers: Map<String, List<String>>): String? {
        val candidates = headers["x-powered-by"].orEmpty() + headers["server"].orEmpty()
        val re = Regex("""PHP/([0-9]+\.[0-9]+\.[0-9]+)""", RegexOption.IGNORE_CASE)
        for (h in candidates) re.find(h)?.let { return it.groupValues[1] }
        return null
    }

    /** True when PHP is in use (X-Powered-By or a PHPSESSID cookie) but no version is exposed. */
    fun phpDetectedWithoutVersion(headers: Map<String, List<String>>): Boolean {
        if (phpVersion(headers) != null) return false
        val powered = headers["x-powered-by"]?.joinToString(" ").orEmpty()
        val cookies = headers["set-cookie"]?.joinToString(" ").orEmpty()
        return powered.contains("PHP", ignoreCase = true) || cookies.contains("PHPSESSID", ignoreCase = true)
    }

    fun phpHiddenFinding(scope: String, host: String): Finding = Finding(
        title = "PHP in use but version hidden", severity = Severity.LOW, source = FindingSource.WEB, scope = scope,
        target = host,
        details = "PHP is in use but its version isn't exposed, so version-based CVE checks (including critical ones like PHP2Shell, CVE-2026-109618/9) can't be confirmed remotely.",
        remediation = "Confirm the PHP version on the server ('php -v') and keep it fully patched. Hiding the version (expose_php = Off) is good practice but isn't a substitute for patching."
    )

    data class CookieInfo(val name: String, val secure: Boolean, val httpOnly: Boolean, val sameSite: String? = null)

    fun parseCookie(header: String): CookieInfo {
        val parts = header.split(";").map { it.trim() }
        val name = parts.firstOrNull()?.substringBefore("=")?.trim().orEmpty().ifBlank { "(unnamed)" }
        val attributes = parts.drop(1).map { it.substringBefore("=").trim().lowercase() }.toSet()
        val sameSite = parts.drop(1).firstOrNull { it.substringBefore("=").trim().equals("samesite", ignoreCase = true) }
            ?.substringAfter("=", "")?.trim()?.lowercase()?.ifBlank { null }
        return CookieInfo(name, secure = "secure" in attributes, httpOnly = "httponly" in attributes, sameSite = sameSite)
    }

    private fun namesOf(cookies: List<CookieInfo>): String {
        val names = cookies.map { it.name }.distinct()
        return names.take(5).joinToString(", ") + if (names.size > 5) " and ${names.size - 5} more" else ""
    }
}
