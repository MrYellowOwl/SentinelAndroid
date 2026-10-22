package com.yellowowl.sentinel

/**
 * Pure logic for the deeper website checks: CORS reflection, security.txt, Subresource Integrity,
 * and a generic sensitive-path sweep. The HTTP requests that feed these live in [WebsiteAuditor].
 */
object WebDeep {
    private fun web(scope: String, host: String, title: String, sev: Severity, details: String, fix: String) =
        Finding(title = title, severity = sev, source = FindingSource.WEB, scope = scope, target = host, details = details, remediation = fix)

    /**
     * CORS verdict from a probe that sent Origin: [sentOrigin].
     * acao = Access-Control-Allow-Origin, acac = Access-Control-Allow-Credentials on the response.
     */
    fun corsFinding(scope: String, host: String, sentOrigin: String, acao: String?, acac: String?): Finding? {
        if (acao == null) return null
        val allowCreds = acac?.trim().equals("true", ignoreCase = true)
        val reflects = acao.trim().equals(sentOrigin, ignoreCase = true)
        return when {
            reflects && allowCreds -> web(scope, host, "CORS reflects arbitrary origin with credentials", Severity.HIGH,
                "The server echoed our test Origin ($sentOrigin) in Access-Control-Allow-Origin and allows credentials, so any site can read authenticated responses.",
                "Never reflect the Origin blindly with credentials; allow only an explicit allow-list of trusted origins.")
            acao.trim() == "*" && allowCreds -> web(scope, host, "CORS wildcard with credentials", Severity.HIGH,
                "Access-Control-Allow-Origin is * together with Allow-Credentials: true (browsers reject this combo, but it signals a broken CORS config).",
                "Return a specific allowed origin, not *, whenever credentials are involved.")
            reflects -> web(scope, host, "CORS reflects the request origin", Severity.MEDIUM,
                "The server echoed our test Origin ($sentOrigin). Without credentials this is lower risk, but it often indicates origin validation is missing.",
                "Validate Origin against an allow-list instead of reflecting it.")
            acao.trim() == "*" -> web(scope, host, "CORS allows any origin (*)", Severity.INFO,
                "Access-Control-Allow-Origin is *. Fine for public, non-credentialed APIs; a risk if the endpoint returns private data.",
                "Restrict to known origins if the endpoint ever returns user-specific data.")
            else -> null
        }
    }

    fun securityTxtFinding(scope: String, host: String, found: Boolean): Finding? =
        if (found) null
        else web(scope, host, "No security.txt", Severity.INFO,
            "No /.well-known/security.txt was found. It's an optional file giving researchers a way to report vulnerabilities.",
            "Publish /.well-known/security.txt with a Contact and (optionally) a disclosure policy (RFC 9116).")

    /** External <script src> tags lacking an integrity attribute, from the page HTML. */
    fun externalScriptsWithoutSri(html: String, pageHost: String): List<String> {
        val scripts = Regex("""<script\b[^>]*>""", RegexOption.IGNORE_CASE).findAll(html).map { it.value }
        return scripts.mapNotNull { tag ->
            val src = Regex("""src\s*=\s*["']([^"']+)["']""", RegexOption.IGNORE_CASE).find(tag)?.groupValues?.get(1) ?: return@mapNotNull null
            val external = src.startsWith("//") || Regex("""^https?://""", RegexOption.IGNORE_CASE).containsMatchIn(src)
            if (!external) return@mapNotNull null
            val sameHost = src.contains("://$pageHost", ignoreCase = true) || src.startsWith("//$pageHost", ignoreCase = true)
            val hasIntegrity = Regex("""\bintegrity\s*=""", RegexOption.IGNORE_CASE).containsMatchIn(tag)
            if (!sameHost && !hasIntegrity) src else null
        }.distinct().toList()
    }

    fun sriFinding(scope: String, host: String, html: String): Finding? {
        val bad = externalScriptsWithoutSri(html, host)
        if (bad.isEmpty()) return null
        return web(scope, host, "Third-party scripts without Subresource Integrity", Severity.LOW,
            "${bad.size} external script(s) load without an integrity hash, so a compromised CDN could serve malicious code: ${bad.take(4).joinToString(", ")}${if (bad.size > 4) "…" else ""}.",
            "Add integrity (SRI hash) + crossorigin attributes to third-party <script> tags, or self-host them.")
    }

    /** Generic sensitive paths worth probing on any site (not just WordPress). */
    data class SensitivePath(val path: String, val severity: Severity, val what: String)
    val sensitivePaths = listOf(
        SensitivePath("/.git/config", Severity.HIGH, "Git repository config exposed — full source/history may be downloadable."),
        SensitivePath("/.env", Severity.HIGH, "Environment file exposed — often contains DB and API credentials."),
        SensitivePath("/.svn/entries", Severity.MEDIUM, "Subversion metadata exposed."),
        SensitivePath("/.DS_Store", Severity.LOW, "macOS directory index exposed — leaks file names."),
        SensitivePath("/backup.zip", Severity.MEDIUM, "Backup archive exposed."),
        SensitivePath("/.well-known/security.txt", Severity.INFO, "security.txt present."),
        SensitivePath("/server-status", Severity.MEDIUM, "Apache server-status exposed — leaks requests and client IPs."),
        SensitivePath("/phpinfo.php", Severity.MEDIUM, "phpinfo() exposed — leaks full server configuration.")
    )

    fun exposedPathFinding(scope: String, host: String, path: SensitivePath): Finding =
        web(scope, host, "Exposed: ${path.path}", path.severity, path.what,
            if (path.severity == Severity.INFO) "No action needed." else "Remove or block access to ${path.path}; it should not be web-reachable.")

    /** If a request for a known-nonexistent path returns 200, the server soft-404s and the sweep is unreliable. */
    fun looksLikeSoftNotFound(randomPathStatus: Int?): Boolean = randomPathStatus == 200

    fun softNotFoundFinding(scope: String, host: String): Finding =
        web(scope, host, "Sensitive-path sweep skipped (server soft-404s)", Severity.INFO,
            "A request for a random nonexistent path returned HTTP 200, so this server answers 200 for everything. The path sweep was skipped to avoid false positives.",
            "Configure the server to return 404 for missing paths so exposure checks are meaningful.")
}
